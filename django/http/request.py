from __future__ import unicode_literals

import copy
import re
import sys
from io import BytesIO
from itertools import chain
from typing import Any, Dict, Iterable, Iterator, List, Optional, overload, Sequence, Tuple, Union, TYPE_CHECKING
from typing import BinaryIO

from django.conf import settings
from django.core import signing
from django.core.exceptions import (
    DisallowedHost, ImproperlyConfigured, RequestDataTooBig,
)
from django.core.files import uploadhandler, uploadedfile
from django.http.multipartparser import MultiPartParser, MultiPartParserError
from django.utils import six
from django.utils.datastructures import ImmutableList, MultiValueDict
from django.utils.encoding import (
    escape_uri_path, force_bytes, force_str, force_text, iri_to_uri,
)
from django.utils.http import is_same_domain, limited_parse_qsl
if TYPE_CHECKING:
    from urllib.parse import quote, urlencode, urljoin, urlsplit
else:
    from django.utils.six.moves.urllib.parse import (
        quote, urlencode, urljoin, urlsplit,
    )

RAISE_ERROR = object()

host_validation_re = re.compile(r"^([a-z0-9.-]+|\[[a-f0-9]*:[a-f0-9:]+\])(:\d+)?$")


class UnreadablePostError(IOError):
    pass


class RawPostDataException(Exception):
    """
    You cannot access raw_post_data from a request that has
    multipart/* POST data if it has been accessed via POST,
    FILES, etc..
    """
    pass

UploadHandlerList = Sequence[uploadhandler.FileUploadHandler]


class HttpRequest(Iterable[bytes]):
    """A basic HTTP request."""

    # The encoding used in GET/POST dicts. None means use default setting.
    _encoding = None  # type: Optional[str]
    _upload_handlers = []  # type: UploadHandlerList

    def __init__(self):
        # type: () -> None
        # WARNING: The `WSGIRequest` subclass doesn't call `super`.
        # Any variable assignment made here should also happen in
        # `WSGIRequest.__init__()`.

        self.GET = QueryDict(mutable=True)
        self.POST = QueryDict(mutable=True)
        self.COOKIES = {}  # type: Dict[str, str]
        self.META = {}  # type: Dict[str, str]
        self.FILES = MultiValueDict()  # type: MultiValueDict[str, uploadedfile.UploadedFile]

        self.path = ''
        self.path_info = ''
        self.method = None  # type: Optional[str]
        self.resolver_match = None
        self._post_parse_error = False
        self.content_type = None  # type: Optional[str]
        self.content_params = None  # type: Optional[Dict[str, str]]

    def __repr__(self):
        # type: () -> str
        if self.method is None or not self.get_full_path():
            return force_str('<%s>' % self.__class__.__name__)
        return force_str(
            '<%s: %s %r>' % (self.__class__.__name__, self.method, force_str(self.get_full_path()))
        )

    def _get_raw_host(self):
        # type: () -> str
        """
        Return the HTTP host using the environment or request headers. Skip
        allowed hosts protection, so may return an insecure host.
        """
        # We try three options, in order of decreasing preference.
        if settings.USE_X_FORWARDED_HOST and (
                'HTTP_X_FORWARDED_HOST' in self.META):
            host = self.META['HTTP_X_FORWARDED_HOST']
        elif 'HTTP_HOST' in self.META:
            host = self.META['HTTP_HOST']
        else:
            # Reconstruct the host using the algorithm from PEP 333.
            host = self.META['SERVER_NAME']
            server_port = self.get_port()
            if server_port != ('443' if self.is_secure() else '80'):
                host = '%s:%s' % (host, server_port)
        return host

    def get_host(self):
        # type: () -> str
        """Return the HTTP host using the environment or request headers."""
        host = self._get_raw_host()

        # There is no hostname validation when DEBUG=True
        if settings.DEBUG:
            return host

        domain, port = split_domain_port(host)
        if domain and validate_host(domain, settings.ALLOWED_HOSTS):
            return host
        else:
            msg = "Invalid HTTP_HOST header: %r." % host
            if domain:
                msg += " You may need to add %r to ALLOWED_HOSTS." % domain
            else:
                msg += " The domain name provided is not valid according to RFC 1034/1035."
            raise DisallowedHost(msg)

    def get_port(self):
        # type: () -> str
        """Return the port number for the request as a string."""
        if settings.USE_X_FORWARDED_PORT and 'HTTP_X_FORWARDED_PORT' in self.META:
            port = self.META['HTTP_X_FORWARDED_PORT']
        else:
            port = self.META['SERVER_PORT']
        return str(port)

    def get_full_path(self, force_append_slash=False):
        # type: (bool) -> str
        # RFC 3986 requires query string arguments to be in the ASCII range.
        # Rather than crash if this doesn't happen, we encode defensively.
        return '%s%s%s' % (
            escape_uri_path(self.path),
            '/' if force_append_slash and not self.path.endswith('/') else '',
            ('?' + iri_to_uri(self.META.get('QUERY_STRING', ''))) if self.META.get('QUERY_STRING', '') else ''
        )

    def get_signed_cookie(self, key, default=RAISE_ERROR, salt='', max_age=None):  # type: ignore
        # type: (str, str, str, Optional[int]) -> str
        """
        Attempts to return a signed cookie. If the signature fails or the
        cookie has expired, raises an exception... unless you provide the
        default argument in which case that value will be returned instead.
        """
        try:
            cookie_value = self.COOKIES[key]
        except KeyError:
            if default is not RAISE_ERROR:
                return default
            else:
                raise
        try:
            value = signing.get_cookie_signer(salt=key + salt).unsign(
                cookie_value, max_age=max_age)
        except signing.BadSignature:
            if default is not RAISE_ERROR:
                return default
            else:
                raise
        return value

    def get_raw_uri(self):
        # type: () -> str
        """
        Return an absolute URI from variables available in this request. Skip
        allowed hosts protection, so may return insecure URI.
        """
        return '{scheme}://{host}{path}'.format(
            scheme=self.scheme,
            host=self._get_raw_host(),
            path=self.get_full_path(),
        )

    def build_absolute_uri(self, location=None):
        # type:  (Optional[str]) -> str
        """
        Builds an absolute URI from the location and the variables available in
        this request. If no ``location`` is specified, the absolute URI is
        built on ``request.get_full_path()``. Anyway, if the location is
        absolute, it is simply converted to an RFC 3987 compliant URI and
        returned and if location is relative or is scheme-relative (i.e.,
        ``//example.com/``), it is urljoined to a base URL constructed from the
        request variables.
        """
        if location is None:
            # Make it an absolute url (but schemeless and domainless) for the
            # edge case that the path starts with '//'.
            location = '//%s' % self.get_full_path()
        bits = urlsplit(location)
        if not (bits.scheme and bits.netloc):
            current_uri = '{scheme}://{host}{path}'.format(scheme=self.scheme,
                                                           host=self.get_host(),
                                                           path=self.path)
            # Join the constructed URL with the provided location, which will
            # allow the provided ``location`` to apply query strings to the
            # base path as well as override the host, if it begins with //
            location = urljoin(current_uri, location)
        return iri_to_uri(location)

    def _get_scheme(self):
        # type: () -> str
        """
        Hook for subclasses like WSGIRequest to implement. Returns 'http' by
        default.
        """
        return 'http'

    @property
    def scheme(self):
        # type: () -> str
        if settings.SECURE_PROXY_SSL_HEADER:
            try:
                header, value = settings.SECURE_PROXY_SSL_HEADER
            except ValueError:
                raise ImproperlyConfigured(
                    'The SECURE_PROXY_SSL_HEADER setting must be a tuple containing two values.'
                )
            if self.META.get(header) == value:
                return 'https'
        return self._get_scheme()

    def is_secure(self):
        # type: () -> bool
        return self.scheme == 'https'

    def is_ajax(self):
        # type: () -> bool
        return self.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest'

    @property
    def encoding(self):
        # type: () -> Optional[str]
        return self._encoding

    @encoding.setter
    def encoding(self, val):
        # type: (Optional[str]) -> None
        """
        Sets the encoding used for GET/POST accesses. If the GET or POST
        dictionary has already been created, it is removed and recreated on the
        next access (so that it is decoded correctly).
        """
        self._encoding = val
        if hasattr(self, '_get'):
            del self._get  # type: ignore
        if hasattr(self, '_post'):
            del self._post  # type: ignore

    def _initialize_handlers(self):
        # type: () -> None
        self._upload_handlers = [uploadhandler.load_handler(handler, self)
                                 for handler in settings.FILE_UPLOAD_HANDLERS]

    @property
    def upload_handlers(self):
        # type: () -> UploadHandlerList
        if not self._upload_handlers:
            # If there are no upload handlers defined, initialize them from settings.
            self._initialize_handlers()
        return self._upload_handlers

    @upload_handlers.setter
    def upload_handlers(self, upload_handlers):
        # type: (UploadHandlerList) -> None
        if hasattr(self, '_files'):
            raise AttributeError("You cannot set the upload handlers after the upload has been processed.")
        self._upload_handlers = upload_handlers

    def parse_file_upload(self, META, post_data):
        # type: (Dict[str, str], BytesIO) -> Tuple[QueryDict, MultiValueDict[str, uploadedfile.UploadedFile]]
        """Returns a tuple of (POST QueryDict, FILES MultiValueDict)."""
        self.upload_handlers = ImmutableList(  # type: ignore  # warning is an argument of __new__, it's accepted
            self.upload_handlers,
            warning="You cannot alter upload handlers after the upload has been processed."
        )
        parser = MultiPartParser(META, post_data, self.upload_handlers, self.encoding)
        return parser.parse()

    @property
    def body(self):
        # type: () -> bytes
        if not hasattr(self, '_body'):
            if self._read_started:
                raise RawPostDataException("You cannot access body after reading from request's data stream")

            # Limit the maximum request data size that will be handled in-memory.
            if (settings.DATA_UPLOAD_MAX_MEMORY_SIZE is not None and
                    int(self.META.get('CONTENT_LENGTH') or 0) > settings.DATA_UPLOAD_MAX_MEMORY_SIZE):
                raise RequestDataTooBig('Request body exceeded settings.DATA_UPLOAD_MAX_MEMORY_SIZE.')

            try:
                self._body = self.read()
            except IOError as e:
                six.reraise(UnreadablePostError, UnreadablePostError(*e.args), sys.exc_info()[2])
            self._stream = BytesIO(self._body)
        return self._body

    def _mark_post_parse_error(self):
        # type: () -> None
        self._post = QueryDict()
        self._files = MultiValueDict()  # type: MultiValueDict[str, uploadedfile.UploadedFile]
        self._post_parse_error = True

    def _load_post_and_files(self):
        # type: () -> None
        """Populate self._post and self._files if the content-type is a form type"""
        if self.method != 'POST':
            self._post, self._files = QueryDict(encoding=self._encoding), MultiValueDict()
            return
        if self._read_started and not hasattr(self, '_body'):
            self._mark_post_parse_error()
            return

        if self.content_type == 'multipart/form-data':
            if hasattr(self, '_body'):
                # Use already read data
                data = BytesIO(self._body)  # type: BinaryIO
            else:
                data = self
            try:
                self._post, self._files = self.parse_file_upload(self.META, data)
            except MultiPartParserError:
                # An error occurred while parsing POST data. Since when
                # formatting the error the request handler might access
                # self.POST, set self._post and self._file to prevent
                # attempts to parse POST data again.
                # Mark that an error occurred. This allows self.__repr__ to
                # be explicit about it instead of simply representing an
                # empty POST
                self._mark_post_parse_error()
                raise
        elif self.content_type == 'application/x-www-form-urlencoded':
            self._post, self._files = QueryDict(self.body, encoding=self._encoding), MultiValueDict()
        else:
            self._post, self._files = QueryDict(encoding=self._encoding), MultiValueDict()

    def close(self):
        # type: () -> None
        if hasattr(self, '_files'):
            for f in chain.from_iterable(l[1] for l in self._files.lists()):
                f.close()

    # File-like and iterator interface.
    #
    # Expects self._stream to be set to an appropriate source of bytes by
    # a corresponding request subclass (e.g. WSGIRequest).
    # Also when request data has already been read by request.POST or
    # request.body, self._stream points to a BytesIO instance
    # containing that data.

    def read(self, *args, **kwargs):
        # type: (*Any, **Any) -> bytes
        self._read_started = True
        try:
            return self._stream.read(*args, **kwargs)
        except IOError as e:
            six.reraise(UnreadablePostError, UnreadablePostError(*e.args), sys.exc_info()[2])
            raise

    def readline(self, *args, **kwargs):
        # type: (*Any, **Any) -> bytes
        self._read_started = True
        try:
            return self._stream.readline(*args, **kwargs)
        except IOError as e:
            six.reraise(UnreadablePostError, UnreadablePostError(*e.args), sys.exc_info()[2])
            raise

    def xreadlines(self):
        # type: () -> Iterator[bytes]
        while True:
            buf = self.readline()
            if not buf:
                break
            yield buf

    __iter__ = xreadlines

    def readlines(self):
        # type: () -> List[bytes]
        return list(iter(self))


class QueryDict(MultiValueDict[str, str]):
    """
    A specialized MultiValueDict which represents a query string.

    A QueryDict can be used to represent GET or POST data. It subclasses
    MultiValueDict since keys in such data can be repeated, for instance
    in the data from a form with a <select multiple> field.

    By default QueryDicts are immutable, though the copy() method
    will always return a mutable copy.

    Both keys and values set on this class are converted from the given encoding
    (DEFAULT_CHARSET by default) to unicode.
    """

    # These are both reset in __init__, but is specified here at the class
    # level so that unpickling will have valid values
    _mutable = True
    _encoding = None  # type: Optional[str]

    def __init__(self, query_string=None, mutable=False, encoding=None):
        # type: (Union[str, bytes, None], bool, Optional[str]) -> None
        super(QueryDict, self).__init__()
        if not encoding:
            encoding = settings.DEFAULT_CHARSET
        self.encoding = encoding
        query_string = query_string or ''
        parse_qsl_kwargs = {
            'keep_blank_values': True,
            'fields_limit': settings.DATA_UPLOAD_MAX_NUMBER_FIELDS,
            'encoding': encoding,
        }
        if six.PY3:
            if isinstance(query_string, bytes):
                # query_string normally contains URL-encoded data, a subset of ASCII.
                try:
                    query_string = query_string.decode(encoding)  # type: ignore
                except UnicodeDecodeError:
                    # ... but some user agents are misbehaving :-(
                    query_string = query_string.decode('iso-8859-1')  # type: ignore
            for key, value in limited_parse_qsl(query_string, **parse_qsl_kwargs):
                self.appendlist(key, value)
        else:
            for key, value in limited_parse_qsl(query_string, **parse_qsl_kwargs):
                try:
                    value = value.decode(encoding)
                except UnicodeDecodeError:
                    value = value.decode('iso-8859-1')
                self.appendlist(force_text(key, encoding, errors='replace'),
                                value)
        self._mutable = mutable

    @property
    def encoding(self):
        # type: () -> str
        if self._encoding is None:
            self._encoding = settings.DEFAULT_CHARSET
        return self._encoding  # type: ignore

    @encoding.setter
    def encoding(self, value):
        # type: (str) -> None
        self._encoding = value

    def _assert_mutable(self):
        # type: () -> None
        if not self._mutable:
            raise AttributeError("This QueryDict instance is immutable")

    def __setitem__(self, key, value):
        # type: (str, str) -> None
        self._assert_mutable()
        key = bytes_to_text(key, self.encoding)
        value = bytes_to_text(value, self.encoding)
        super(QueryDict, self).__setitem__(key, value)

    def __delitem__(self, key):
        # type: (str) -> None
        self._assert_mutable()
        super(QueryDict, self).__delitem__(key)

    def __copy__(self):
        # type: () -> QueryDict
        result = self.__class__('', mutable=True, encoding=self.encoding)
        for key, value in six.iterlists(self):
            result.setlist(key, value)
        return result

    def __deepcopy__(self, memo):
        # type: (Dict[int, object]) -> QueryDict
        result = self.__class__('', mutable=True, encoding=self.encoding)
        memo[id(self)] = result
        for key, value in six.iterlists(self):
            result.setlist(copy.deepcopy(key, memo), copy.deepcopy(value, memo))
        return result

    def setlist(self, key, list_):
        # type: (str, List[str]) -> None
        self._assert_mutable()
        key = bytes_to_text(key, self.encoding)
        list_ = [bytes_to_text(elt, self.encoding) for elt in list_]
        super(QueryDict, self).setlist(key, list_)

    def setlistdefault(self, key, default_list=None):
        # type: (str, Optional[List[str]]) -> List[str]
        self._assert_mutable()
        return super(QueryDict, self).setlistdefault(key, default_list)

    def appendlist(self, key, value):
        # type: (str, str) -> None
        self._assert_mutable()
        key = bytes_to_text(key, self.encoding)
        value = bytes_to_text(value, self.encoding)
        super(QueryDict, self).appendlist(key, value)

    def pop(self, key, *args):  # type: ignore  # return type was overridden by MultiValueDict
        # type: (str, *Any) -> List[str]
        self._assert_mutable()
        return super(QueryDict, self).pop(key, *args)

    def popitem(self):
        # type: () -> Tuple[str, str]
        self._assert_mutable()
        return super(QueryDict, self).popitem()

    def clear(self):
        # type: () -> None
        self._assert_mutable()
        super(QueryDict, self).clear()

    def setdefault(self, key, default=None):
        # type: (str, Optional[str]) -> str
        self._assert_mutable()
        key = bytes_to_text(key, self.encoding)
        default = bytes_to_text(default, self.encoding)
        return super(QueryDict, self).setdefault(key, default)

    def copy(self):
        # type: () -> QueryDict
        """Returns a mutable copy of this object."""
        return self.__deepcopy__({})

    def urlencode(self, safe=None):
        # type: (Optional[str]) -> str
        """
        Returns an encoded string of all query string arguments.

        :arg safe: Used to specify characters which do not require quoting, for
            example::

                >>> q = QueryDict(mutable=True)
                >>> q['next'] = '/a&b/'
                >>> q.urlencode()
                'next=%2Fa%26b%2F'
                >>> q.urlencode(safe='/')
                'next=/a%26b/'
        """
        output = []  # type: List[str]
        if safe:
            safe = force_bytes(safe, self.encoding)

            def encode(k, v):
                # type: (str, str) -> str
                return '%s=%s' % ((quote(k, safe), quote(v, safe)))
        else:
            def encode(k, v):
                # type: (str, str) -> str
                return urlencode({k: v})
        for k, list_ in self.lists():
            k = force_bytes(k, self.encoding)
            output.extend(encode(k, force_bytes(v, self.encoding))
                          for v in list_)
        return '&'.join(output)


# It's neither necessary nor appropriate to use
# django.utils.encoding.smart_text for parsing URLs and form inputs. Thus,
# this slightly more restricted function, used by QueryDict.
@overload
def bytes_to_text(s, encoding):
    # type: (None, str) -> None
    ...
@overload
def bytes_to_text(s, encoding):
    # type: (str, str) -> str
    ...
def bytes_to_text(s, encoding):  # type: ignore  # some abuse here of @overload
    # type: (bytes, str) -> str
    """
    Converts basestring objects to unicode, using the given encoding. Illegally
    encoded input characters are replaced with Unicode "unknown" codepoint
    (\ufffd).

    Returns any non-basestring objects without change.
    """
    if isinstance(s, bytes):
        return six.text_type(s, encoding, 'replace')
    else:
        return s


def split_domain_port(host):
    # type: (str) -> Tuple[str, str]
    """
    Return a (domain, port) tuple from a given host.

    Returned domain is lower-cased. If the host is invalid, the domain will be
    empty.
    """
    host = host.lower()

    if not host_validation_re.match(host):
        return '', ''

    if host[-1] == ']':
        # It's an IPv6 address without a port.
        return host, ''
    bits = host.rsplit(':', 1)
    if len(bits) == 2:
        return tuple(bits)  # type: ignore
    return bits[0], ''


def validate_host(host, allowed_hosts):
    # type: (str, Iterable[str]) -> bool
    """
    Validate the given host for this site.

    Check that the host looks valid and matches a host or host pattern in the
    given list of ``allowed_hosts``. Any pattern beginning with a period
    matches a domain and all its subdomains (e.g. ``.example.com`` matches
    ``example.com`` and any subdomain), ``*`` matches anything, and anything
    else must match exactly.

    Note: This function assumes that the given host is lower-cased and has
    already had the port, if any, stripped off.

    Return ``True`` for a valid host, ``False`` otherwise.
    """
    host = host[:-1] if host.endswith('.') else host

    for pattern in allowed_hosts:
        if pattern == '*' or is_same_domain(host, pattern):
            return True

    return False
