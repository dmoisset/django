from __future__ import unicode_literals

from typing import Dict, Set, Mapping, Union, TYPE_CHECKING
import sys

from django.utils import six
from django.utils.encoding import force_str
if TYPE_CHECKING:
    import http.cookies as http_cookies
else:
    from django.utils.six.moves import http_cookies

# http://bugs.python.org/issue2193 is fixed in Python 3.3+.
_cookie_allows_colon_in_names = six.PY3

# Cookie pickling bug is fixed in Python 2.7.9 and Python 3.4.3+
# http://bugs.python.org/issue22775
cookie_pickles_properly = (
    (sys.version_info[:2] == (2, 7) and sys.version_info >= (2, 7, 9)) or
    sys.version_info >= (3, 4, 3)
)

if _cookie_allows_colon_in_names and cookie_pickles_properly:
    SimpleCookie = http_cookies.SimpleCookie
else:
    Morsel = http_cookies.Morsel

    class SimpleCookie(http_cookies.SimpleCookie):  # type: ignore  # allow redefinition of class
        if not cookie_pickles_properly:
            def __setitem__(self, key: str, value: Union[str, Morsel]) -> None:
                # Apply the fix from http://bugs.python.org/issue22775 where
                # it's not fixed in Python itself
                if isinstance(value, Morsel):
                    # allow assignment of constructed Morsels (e.g. for pickling)
                    dict.__setitem__(self, key, value)  # type: ignore
                else:
                    super(SimpleCookie, self).__setitem__(key, value)

        if not _cookie_allows_colon_in_names:
            def load(self, rawdata: Union[str, Mapping[str, Union[str, 'Morsel']]]) -> None:
                self.bad_cookies = set()  # type: Set[str]
                if isinstance(rawdata, six.text_type):
                    rawdata = force_str(rawdata)
                super(SimpleCookie, self).load(rawdata)
                for key in self.bad_cookies:
                    del self[key]

            # override private __set() method:
            # (needed for using our Morsel, and for laxness with CookieError
            def _BaseCookie__set(self, key: str, real_value: str, coded_value: str) -> None:
                key = force_str(key)
                try:
                    M = self.get(key, Morsel())
                    M.set(key, real_value, coded_value)
                    dict.__setitem__(self, key, M)  # type: ignore
                except http_cookies.CookieError:
                    if not hasattr(self, 'bad_cookies'):
                        self.bad_cookies = set()
                    self.bad_cookies.add(key)
                    dict.__setitem__(self, key, http_cookies.Morsel())  # type: ignore


def parse_cookie(cookie):
    # type: (str) -> Dict[str, str]
    """
    Return a dictionary parsed from a `Cookie:` header string.
    """
    cookiedict = {}
    if six.PY2:
        cookie = force_str(cookie)
    for chunk in cookie.split(str(';')):
        if str('=') in chunk:
            key, val = chunk.split(str('='), 1)
        else:
            # Assume an empty name per
            # https://bugzilla.mozilla.org/show_bug.cgi?id=169091
            key, val = str(''), chunk
        key, val = key.strip(), val.strip()
        if key or val:
            # unquote using Python's algorithm.
            cookiedict[key] = http_cookies._unquote(val)  # type: ignore  # type: using undocumented method
    return cookiedict
