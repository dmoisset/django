from __future__ import unicode_literals

import datetime
import json
from json import JSONEncoder
import re
import sys
import time

from typing import Any, AnyStr, Dict, Iterable, Iterator, IO, List, Optional, overload, Tuple, Type, Union, TYPE_CHECKING

from email.header import Header

from django.conf import settings
from django.core import signals, signing
from django.core.exceptions import DisallowedRedirect
from django.core.serializers.json import DjangoJSONEncoder
from django.http.cookie import SimpleCookie
from django.utils import timezone
import six
from django.utils.encoding import (
    force_bytes, force_str, force_text, iri_to_uri,
)
from django.utils.http import cookie_date
if TYPE_CHECKING:
    from http.client import responses
    from urllib.parse import urlparse
else:
    from django.utils.six.moves import map
    from django.utils.six.moves.http_client import responses
    from django.utils.six.moves.urllib.parse import urlparse

_charset_from_content_type_re = re.compile(r';\s*charset=(?P<charset>[^\s;]+)', re.I)


class BadHeaderError(ValueError):
    pass


class HttpResponseBase(six.Iterator):
    """
    An HTTP response base class with dictionary-accessed headers.

    This class doesn't handle content. It should not be used directly.
    Use the HttpResponse and StreamingHttpResponse subclasses instead.
    """

    status_code = 200

    def __init__(self, content_type=None, status=None, reason=None, charset=None):
        # type: (Optional[str], Optional[int], Optional[str], Optional[str]) -> None
        # _headers is a mapping of the lower-case name to the original case of
        # the header (required for working with legacy systems) and the header
        # value. Both the name of the header and its value are ASCII strings.
        self._headers = {}  # type: Dict[str, Tuple[str, str]]
        self._closable_objects = []  # type: List[IO]
        # This parameter is set by the handler. It's necessary to preserve the
        # historical behavior of request_finished.
        self._handler_class = None
        self.cookies = SimpleCookie()
        self.closed = False
        if status is not None:
            self.status_code = status
        self._reason_phrase = reason
        self._charset = charset
        if content_type is None:
            content_type = '%s; charset=%s' % (settings.DEFAULT_CONTENT_TYPE,
                                               self.charset)
        self['Content-Type'] = content_type

    @property
    def reason_phrase(self):
        # type: () -> str
        if self._reason_phrase is not None:
            return self._reason_phrase
        # Leave self._reason_phrase unset in order to use the default
        # reason phrase for status code.
        return responses.get(self.status_code, 'Unknown Status Code')

    @reason_phrase.setter
    def reason_phrase(self, value):
        # type: (str) -> None
        self._reason_phrase = value

    @property
    def charset(self):
        # type: () -> str
        if self._charset is not None:
            return self._charset
        content_type = self.get('Content-Type', '')
        matched = _charset_from_content_type_re.search(content_type)
        if matched:
            # Extract the charset and strip its double quotes
            return matched.group('charset').replace('"', '')
        return settings.DEFAULT_CHARSET

    @charset.setter
    def charset(self, value):
        # type: (str) -> None
        self._charset = value

    def serialize_headers(self):
        # type: () -> bytes
        """HTTP headers as a bytestring."""
        def to_bytes(val, encoding):
            # type: (Union[str, bytes], str) -> bytes
            return val if isinstance(val, bytes) else val.encode(encoding)

        headers = [
            (b': '.join([to_bytes(key, 'ascii'), to_bytes(value, 'latin-1')]))
            for key, value in self._headers.values()
        ]
        return b'\r\n'.join(headers)

    if six.PY3:
        __bytes__ = serialize_headers
    else:
        __str__ = serialize_headers

    def _convert_to_charset(self, value, charset, mime_encode=False):
        # type: (object, str, bool) -> str
        """Converts headers key/value to ascii/latin-1 native strings.

        `charset` must be 'ascii' or 'latin-1'. If `mime_encode` is True and
        `value` can't be represented in the given charset, MIME-encoding
        is applied.
        """
        if not isinstance(value, (bytes, six.text_type)):
            value = str(value)
        if ((isinstance(value, bytes) and (b'\n' in value or b'\r' in value)) or
                isinstance(value, six.text_type) and ('\n' in value or '\r' in value)):
            raise BadHeaderError("Header values can't contain newlines (got %r)" % value)
        try:
            if six.PY3:
                if isinstance(value, str):
                    # Ensure string is valid in given charset
                    value.encode(charset)
                else:
                    # Convert bytestring using given charset
                    value = value.decode(charset)
            else:
                if isinstance(value, str):
                    # Ensure string is valid in given charset
                    value.decode(charset)
                else:
                    # Convert unicode string to given charset
                    value = value.encode(charset)
        except UnicodeError as e:
            if mime_encode:
                # Wrapping in str() is a workaround for #12422 under Python 2.
                value = str(Header(value, 'utf-8', maxlinelen=sys.maxsize).encode())
            else:
                e.reason += ', HTTP response headers must be in %s format' % charset  # type: ignore  # reason attribute mising in stdlib typesheds
                raise
        assert isinstance(value, str)
        return value

    def __setitem__(self, header, value):
        # type: (str, Union[str, bytes]) -> None
        header = self._convert_to_charset(header, 'ascii')
        value = self._convert_to_charset(value, 'latin-1', mime_encode=True)
        self._headers[header.lower()] = (header, value)

    def __delitem__(self, header):
        # type: (str) -> None
        try:
            del self._headers[header.lower()]
        except KeyError:
            pass

    def __getitem__(self, header):
        # type: (str) -> str
        return self._headers[header.lower()][1]

    def has_header(self, header):
        # type: (str) -> bool
        """Case-insensitive check for a header."""
        return header.lower() in self._headers

    __contains__ = has_header

    def items(self):
        # type: () -> Iterable[Tuple[str, str]]
        return self._headers.values()

    @overload
    def get(self, header, alternate):
        # type: (str, str) -> str
        ...
    @overload
    def get(self, header):
        # type: (str) -> Optional[str]
        ...
    def get(self, header, alternate=None):  # type: ignore  # abusing @overload a little bit
        return self._headers.get(header.lower(), ('', alternate))[1]

    def set_cookie(self, key: str, value: str='', max_age: int=None,
                   expires: Union[None, str, datetime.datetime]=None, path: str='/',
                   domain: str=None, secure: bool=False, httponly: bool=False) -> None:
        """
        Sets a cookie.

        ``expires`` can be:
        - a string in the correct format,
        - a naive ``datetime.datetime`` object in UTC,
        - an aware ``datetime.datetime`` object in any time zone.
        If it is a ``datetime.datetime`` object then ``max_age`` will be calculated.
        """
        value = force_str(value)
        self.cookies[key] = value
        if expires is not None:
            if isinstance(expires, datetime.datetime):
                if timezone.is_aware(expires):
                    expires = timezone.make_naive(expires, timezone.utc)
                delta = expires - expires.utcnow()
                # Add one second so the date matches exactly (a fraction of
                # time gets lost between converting to a timedelta and
                # then the date string).
                delta = delta + datetime.timedelta(seconds=1)
                # Just set max_age - the max_age logic will set expires.
                expires = None
                max_age = max(0, delta.days * 86400 + delta.seconds)
            else:
                self.cookies[key]['expires'] = expires
        else:
            self.cookies[key]['expires'] = ''
        if max_age is not None:
            self.cookies[key]['max-age'] = max_age
            # IE requires expires, so set it if hasn't been already.
            if not expires:
                self.cookies[key]['expires'] = cookie_date(time.time() +
                                                           max_age)
        if path is not None:
            self.cookies[key]['path'] = path
        if domain is not None:
            self.cookies[key]['domain'] = domain
        if secure:
            self.cookies[key]['secure'] = True
        if httponly:
            self.cookies[key]['httponly'] = True

    def setdefault(self, key, value):
        # type: (str, str) -> None
        """Sets a header unless it has already been set."""
        if key not in self:
            self[key] = value

    def set_signed_cookie(self, key, value, salt='', **kwargs):
        # type: (str, str, str, **Any) -> None
        value = signing.get_cookie_signer(salt=key + salt).sign(value)
        return self.set_cookie(key, value, **kwargs)

    def delete_cookie(self, key, path='/', domain=None):
        # type: (str, str, Optional[str]) -> None
        self.set_cookie(key, max_age=0, path=path, domain=domain,
                        expires='Thu, 01-Jan-1970 00:00:00 GMT')

    # Common methods used by subclasses

    def make_bytes(self, value):
        # type: (object) -> bytes
        """Turn a value into a bytestring encoded in the output charset."""
        # Per PEP 3333, this response body must be bytes. To avoid returning
        # an instance of a subclass, this function returns `bytes(value)`.
        # This doesn't make a copy when `value` already contains bytes.

        # Handle string types -- we can't rely on force_bytes here because:
        # - under Python 3 it attempts str conversion first
        # - when self._charset != 'utf-8' it re-encodes the content
        if isinstance(value, bytes):
            return bytes(value)
        if isinstance(value, six.text_type):
            return bytes(value.encode(self.charset))

        # Handle non-string types (#16494)
        return force_bytes(value, self.charset)

    # These methods partially implement the file-like object interface.
    # See https://docs.python.org/3/library/io.html#io.IOBase

    # The WSGI server must call this method upon completion of the request.
    # See http://blog.dscpl.com.au/2012/10/obligations-for-calling-close-on.html
    def close(self):
        # type: () -> None
        for closable in self._closable_objects:
            try:
                closable.close()
            except Exception:
                pass
        self.closed = True
        signals.request_finished.send(sender=self._handler_class)

    def write(self, content):
        # type: (object) -> None
        raise IOError("This %s instance is not writable" % self.__class__.__name__)

    def flush(self):
        # type: () -> None
        pass

    def tell(self):
        # type: () -> int
        raise IOError("This %s instance cannot tell its position" % self.__class__.__name__)

    # These methods partially implement a stream-like object interface.
    # See https://docs.python.org/library/io.html#io.IOBase

    def readable(self):
        # type: () -> bool
        return False

    def seekable(self):
        # type: () -> bool
        return False

    def writable(self):
        # type: () -> bool
        return False

    def writelines(self, lines):
        # type: (Iterable[object]) -> None
        raise IOError("This %s instance is not writable" % self.__class__.__name__)


class HttpResponse(HttpResponseBase):
    """
    An HTTP response class with a string as content.

    This content that can be read, appended to or replaced.
    """

    streaming = False

    def __init__(self, content=b'', *args, **kwargs):
        # type: (object, *Any, **Any) -> None
        super(HttpResponse, self).__init__(*args, **kwargs)
        # Content is a bytestring. See the `content` property methods.
        self.content = content

    def __repr__(self):
        # type: () -> str
        return '<%(cls)s status_code=%(status_code)d, "%(content_type)s">' % {
            'cls': self.__class__.__name__,
            'status_code': self.status_code,
            'content_type': self['Content-Type'],
        }

    def serialize(self):
        # type: () -> bytes
        """Full HTTP message, including headers, as a bytestring."""
        return self.serialize_headers() + b'\r\n\r\n' + self.content

    if six.PY3:
        __bytes__ = serialize
    else:
        __str__ = serialize

    @property
    def content(self):
        # type: () -> bytes
        return b''.join(self._container)

    @content.setter
    def content(self, value):
        # type: (Any) -> None
        # Consume iterators upon assignment to allow repeated iteration.
        if hasattr(value, '__iter__') and not isinstance(value, (bytes, six.string_types)):  # type: ignore # isinstance typeshed is too restrictive
            content = b''.join(self.make_bytes(chunk) for chunk in value)
            if hasattr(value, 'close'):
                try:
                    value.close()
                except Exception:
                    pass
        else:
            content = self.make_bytes(value)
        # Create a list of properly encoded bytestrings to support write().
        self._container = [content]

    def __iter__(self):
        # type: () -> Iterator[bytes]
        return iter(self._container)

    def write(self, content):
        # type: (object) -> None
        self._container.append(self.make_bytes(content))

    def tell(self):
        # type: () -> int
        return len(self.content)

    def getvalue(self):
        # type: () -> bytes
        return self.content

    def writable(self):
        # type: () -> bool
        return True

    def writelines(self, lines):
        # type: (Iterable[object]) -> None
        for line in lines:
            self.write(line)


class StreamingHttpResponse(HttpResponseBase):
    """
    A streaming HTTP response class with an iterator as content.

    This should only be iterated once, when the response is streamed to the
    client. However, it can be appended to or replaced with a new iterator
    that wraps the original content (or yields entirely new content).
    """

    streaming = True

    def __init__(self, streaming_content=(), *args, **kwargs):
        # type: (Iterable[bytes], *Any, **Any) -> None
        super(StreamingHttpResponse, self).__init__(*args, **kwargs)
        # `streaming_content` should be an iterable of bytestrings.
        # See the `streaming_content` property methods.
        self.streaming_content = streaming_content

    @property
    def content(self):
        # type: () -> bytes
        raise AttributeError(
            "This %s instance has no `content` attribute. Use "
            "`streaming_content` instead." % self.__class__.__name__
        )

    @property
    def streaming_content(self):
        # type: () -> Iterator[bytes]
        return map(self.make_bytes, self._iterator)

    @streaming_content.setter
    def streaming_content(self, value):
        # type: (Iterable[bytes]) -> None
        self._set_streaming_content(value)

    def _set_streaming_content(self, value):
        # type: (Iterable[bytes]) -> None
        # Ensure we can never iterate on "value" more than once.
        self._iterator = iter(value)
        if hasattr(value, 'close'):
            self._closable_objects.append(value)  # type: ignore  # Assuming that having close implies it's a stream

    def __iter__(self):
        # type: () -> Iterator[bytes]
        return self.streaming_content

    def getvalue(self):
        # type: () -> bytes
        return b''.join(self.streaming_content)


class FileResponse(StreamingHttpResponse):
    """
    A streaming HTTP response class optimized for files.
    """
    block_size = 4096

    def _set_streaming_content(self, value):
        # type: (Iterable[bytes]) -> None
        if hasattr(value, 'read'):
            self.file_to_stream = value  # type: Optional[Iterable[bytes]]
            filelike = value
            if hasattr(filelike, 'close'):
                self._closable_objects.append(filelike)  # type: ignore  # Assuming that having close implies it's a stream
            value = iter(lambda: filelike.read(self.block_size), b'')  # type: ignore  # We've checked that it has a read method
        else:
            self.file_to_stream = None
        super(FileResponse, self)._set_streaming_content(value)


class HttpResponseRedirectBase(HttpResponse):
    allowed_schemes = ['http', 'https', 'ftp']

    def __init__(self, redirect_to, *args, **kwargs):
        # type: (str, *Any, **Any) -> None
        parsed = urlparse(force_text(redirect_to))
        if parsed.scheme and parsed.scheme not in self.allowed_schemes:
            raise DisallowedRedirect("Unsafe redirect to URL with protocol '%s'" % parsed.scheme)
        super(HttpResponseRedirectBase, self).__init__(*args, **kwargs)
        self['Location'] = iri_to_uri(redirect_to)

    url = property(lambda self: self['Location'])

    def __repr__(self):
        # type: () -> str
        return '<%(cls)s status_code=%(status_code)d, "%(content_type)s", url="%(url)s">' % {
            'cls': self.__class__.__name__,
            'status_code': self.status_code,
            'content_type': self['Content-Type'],
            'url': self.url,
        }


class HttpResponseRedirect(HttpResponseRedirectBase):
    status_code = 302


class HttpResponsePermanentRedirect(HttpResponseRedirectBase):
    status_code = 301


class HttpResponseNotModified(HttpResponse):
    status_code = 304

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None
        super(HttpResponseNotModified, self).__init__(*args, **kwargs)
        del self['content-type']

    @HttpResponse.content.setter  # type: ignore  # mypy gets confused by this property override
    def content(self, value):  # type: ignore  # mypy gets confused by this property override
        # type: (bytes) -> None
        if value:
            raise AttributeError("You cannot set content to a 304 (Not Modified) response")
        self._container = []


class HttpResponseBadRequest(HttpResponse):
    status_code = 400


class HttpResponseNotFound(HttpResponse):
    status_code = 404


class HttpResponseForbidden(HttpResponse):
    status_code = 403


class HttpResponseNotAllowed(HttpResponse):
    status_code = 405

    def __init__(self, permitted_methods, *args, **kwargs):
        # type: (Iterable[str], *Any, **Any) -> None
        super(HttpResponseNotAllowed, self).__init__(*args, **kwargs)
        self['Allow'] = ', '.join(permitted_methods)

    def __repr__(self):
        # type: () -> str
        return '<%(cls)s [%(methods)s] status_code=%(status_code)d, "%(content_type)s">' % {
            'cls': self.__class__.__name__,
            'status_code': self.status_code,
            'content_type': self['Content-Type'],
            'methods': self['Allow'],
        }


class HttpResponseGone(HttpResponse):
    status_code = 410


class HttpResponseServerError(HttpResponse):
    status_code = 500


class Http404(Exception):
    pass


class JsonResponse(HttpResponse):
    """
    An HTTP response class that consumes data to be serialized to JSON.

    :param data: Data to be dumped into json. By default only ``dict`` objects
      are allowed to be passed due to a security flaw before EcmaScript 5. See
      the ``safe`` parameter for more information.
    :param encoder: Should be an json encoder class. Defaults to
      ``django.core.serializers.json.DjangoJSONEncoder``.
    :param safe: Controls if only ``dict`` objects may be serialized. Defaults
      to ``True``.
    :param json_dumps_params: A dictionary of kwargs passed to json.dumps().
    """

    def __init__(self, data, encoder=DjangoJSONEncoder, safe=True,
                 json_dumps_params=None, **kwargs):
        # type: (object, Type[JSONEncoder], bool, Optional[Dict[str, Any]], **Any) -> None
        if safe and not isinstance(data, dict):
            raise TypeError(
                'In order to allow non-dict objects to be serialized set the '
                'safe parameter to False.'
            )
        if json_dumps_params is None:
            json_dumps_params = {}
        kwargs.setdefault('content_type', 'application/json')
        data = json.dumps(data, cls=encoder, **json_dumps_params)
        super(JsonResponse, self).__init__(content=data, **kwargs)
