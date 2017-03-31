import copy
from collections import OrderedDict

from django.utils import six

from typing import (Any, Callable, Dict, Generic, Hashable, Iterable, Iterator, List,
                    MutableMapping, Mapping, MutableSet, AbstractSet,
                    Optional, overload, Tuple, TypeVar, Union)

KT = TypeVar('KT')
VT = TypeVar('VT')


class OrderedSet(MutableSet[KT], Generic[KT]):
    """
    A set which keeps the ordering of the inserted items.
    Currently backs onto OrderedDict.
    """

    def __init__(self, iterable=None):
        # type: (Optional[Iterable[KT]]) -> None
        items = ((x, None) for x in iterable) if iterable else []  # type: Iterable[Tuple[KT, None]]
        self.dict = OrderedDict(items)  # type: OrderedDict[KT, None]

    def add(self, item):
        # type: (KT) -> None
        self.dict[item] = None

    def remove(self, item):
        # type: (KT) -> None
        del self.dict[item]

    def discard(self, item):
        # type: (KT) -> None
        try:
            self.remove(item)
        except KeyError:
            pass

    def __iter__(self):
        # type: () -> Iterator[KT]
        return iter(self.dict.keys())

    def __contains__(self, item):
        # type: (object) -> bool
        return item in self.dict

    def __bool__(self):
        # type: () -> bool
        return bool(self.dict)

    def __nonzero__(self):
        # type: () -> bool
        return type(self).__bool__(self)

    def __len__(self):
        # type: () -> int
        return len(self.dict)


class MultiValueDictKeyError(KeyError):
    pass


class MultiValueDict(MutableMapping[KT, VT], Generic[KT, VT]):
    """
    A subclass of dictionary customized to handle multiple values for the
    same key.

    >>> d = MultiValueDict({'name': ['Adrian', 'Simon'], 'position': ['Developer']})
    >>> d['name']
    'Simon'
    >>> d.getlist('name')
    ['Adrian', 'Simon']
    >>> d.getlist('doesnotexist')
    []
    >>> d.getlist('doesnotexist', ['Adrian', 'Simon'])
    ['Adrian', 'Simon']
    >>> d.get('lastname', 'nonexistent')
    'nonexistent'
    >>> d.setlist('lastname', ['Holovaty', 'Willison'])

    This class exists to solve the irritating problem raised by cgi.parse_qs,
    which returns a list for every key, even though most Web forms submit
    single name-value pairs.
    """

    def __init__(self, key_to_list_mapping=()):
        # type: (Iterable[Tuple[KT, List[VT]]]) -> None
        self._contents = dict(key_to_list_mapping)

    def __repr__(self):
        # type: () -> str
        return "<%s: %s>" % (self.__class__.__name__,
                             repr(self._contents))

    def __getitem__(self, key):  # type: ignore
        # type: (KT) -> Union[VT, List[VT]]
        """
        Returns the last data value for this key, or [] if it's an empty list;
        raises KeyError if not found.
        """
        try:
            list_ = self._contents[key]
        except KeyError:
            raise MultiValueDictKeyError(repr(key))
        try:
            return list_[-1]
        except IndexError:
            return []

    def __setitem__(self, key, value):
        # type: (KT, VT) -> None
        self._contents[key] = [value]

    def __delitem__(self, key):
        # type: (KT) -> None
        del self._contents[key]

    def __eq__(self, other):
        # type: (object) -> bool
        return self._contents == other

    def __iter__(self):
        # type: () -> Iterator[KT]
        return iter(self._contents)

    def keys(self):
        # type: () -> AbstractSet[KT]
        return self._contents.keys()

    def __len__(self):
        # type: () -> int
        return len(self._contents)

    def pop(self, key, default=None):  # type: ignore
        # type: (KT, Optional[List[VT]]) -> List[VT]
        return self._contents.pop(key, default)

    def __contains__(self, item):
        # type: (object) -> bool
        return item in self._contents

    def clear(self):
        # type: () -> None
        self._contents.clear()

    def __copy__(self):
        # type: () -> MultiValueDict[KT, VT]
        return self.__class__([
            (k, v[:])
            for k, v in self.lists()
        ])

    def __deepcopy__(self, memo=None):
        # type: (Optional[Dict[int, object]]) -> MultiValueDict[KT, VT]
        if memo is None:
            memo = {}
        result = self.__class__()
        memo[id(self)] = result
        for key, value in self._contents.items():
            result._contents[copy.deepcopy(key, memo)] = copy.deepcopy(value, memo)
        return result

    def __getstate__(self):
        # type: () -> Dict[str, Any]
        obj_dict = self.__dict__.copy()
        obj_dict['_contents'] = {k: self.getlist(k) for k in self}
        return obj_dict

    def __setstate__(self, obj_dict):
        # type: (Dict[str, Any]) -> None
        self.__dict__.update(obj_dict)

    def get(self, key, default=None):  # type: ignore
        # type: (KT, Optional[VT]) -> Union[Optional[VT], List[VT]]
        """
        Returns the last data value for the passed key. If key doesn't exist
        or value is an empty list, then default is returned.
        """
        try:
            val = self[key]
        except KeyError:
            return default
        if val == []:
            return default
        return val

    def getlist(self, key, default=None):
        # type: (KT, Optional[List[VT]]) -> List[VT]
        """
        Returns the list of values for the passed key. If key doesn't exist,
        then a default value is returned.
        """
        try:
            return self._contents[key]
        except KeyError:
            if default is None:
                return []
            return default

    def setlist(self, key, list_):
        # type: (KT, List[VT]) -> None
        self._contents[key] = list_

    def setdefault(self, key, default=None):
        # type: (KT, Optional[VT]) -> VT
        if key not in self._contents:
            self[key] = default  # type: ignore
            # Do not return default here because __setitem__() may store
            # another value -- QueryDict.__setitem__() does. Look it up.
        return self[key]  # type: ignore  # key always exists, so can't be [] instead of VT

    def setlistdefault(self, key, default_list=None):
        # type: (KT, Optional[List[VT]]) -> List[VT]
        if key not in self._contents:
            if default_list is None:
                default_list = []
            self.setlist(key, default_list)
            # Do not return default_list here because setlist() may store
            # another value -- QueryDict.setlist() does. Look it up.
        return self.getlist(key)

    def appendlist(self, key, value):
        # type: (KT, VT) -> None
        """Appends an item to the internal list associated with key."""
        self.setlistdefault(key).append(value)

    def _iteritems(self):
        # type: () -> Iterator[Tuple[KT, VT]]
        """
        Yields (key, value) pairs, where value is the last item in the list
        associated with the key.
        """
        for key in self._contents:
            yield key, self[key]  # type: ignore # key exists, so self[key] is VT, not []

    def _iterlists(self):
        # type: () -> Iterable[Tuple[KT, List[VT]]]
        """Yields (key, list) pairs."""
        return six.iteritems(self._contents)

    def _itervalues(self):
        # type: () -> Iterable[VT]
        """Yield the last value on every key list."""
        for key in self._contents:
            yield self[key]  # type: ignore # key exists, so self[key] is VT, not []

    if six.PY3:
        items = _iteritems
        lists = _iterlists
        values = _itervalues
    else:
        iteritems = _iteritems
        iterlists = _iterlists
        itervalues = _itervalues

        def items(self):
            return list(self.iteritems())

        def lists(self):
            return list(self.iterlists())

        def values(self):
            return list(self.itervalues())

    def copy(self):
        # type: () -> MultiValueDict[KT, VT]
        """Returns a shallow copy of this object."""
        return copy.copy(self)

    def update(self, *args, **kwargs):  # type: ignore
        # type: (*Mapping[KT, VT], **Iterable[Tuple[KT, VT]]) -> None
        """
        update() extends rather than replaces existing key lists.
        Also accepts keyword args.
        """
        if len(args) > 1:
            raise TypeError("update expected at most 1 arguments, got %d" % len(args))
        if args:
            other_dict = args[0]
            if isinstance(other_dict, MultiValueDict):
                for key, value_list in other_dict.lists():
                    self.setlistdefault(key).extend(value_list)
            else:
                try:
                    for key, value in other_dict.items():
                        self.setlistdefault(key).append(value)
                except TypeError:
                    raise ValueError("MultiValueDict.update() takes either a MultiValueDict or dictionary")
        for key, value in six.iteritems(kwargs):
            self.setlistdefault(key).append(value)

    def dict(self):
        # type: () -> Dict[KT, Union[VT, List[VT]]]
        """
        Returns current object as a dict with singular values.
        """
        return {key: self[key] for key in self._contents}


class ImmutableList(tuple, Generic[VT]):
    """
    A tuple-like object that raises useful errors when it is asked to mutate.

    Example::

        >>> a = ImmutableList(range(5), warning="You cannot mutate this.")
        >>> a[3] = '4'
        Traceback (most recent call last):
            ...
        AttributeError: You cannot mutate this.
    """

    warning = 'ImmutableList object is immutable.'

    def __new__(cls, *args: Any, **kwargs: Any) -> 'ImmutableList[VT]':
        if 'warning' in kwargs:
            warning = kwargs['warning']
            del kwargs['warning']
        else:
            warning = 'ImmutableList object is immutable.'
        self = tuple.__new__(cls, *args, **kwargs)  # type: ignore  # This call is ok
        self.warning = warning
        return self

    def complain(self, *wargs: Any, **kwargs: Any) -> None:
        if isinstance(self.warning, Exception):
            raise self.warning
        else:
            raise AttributeError(self.warning)

    # All list mutation functions complain.
    __delitem__ = complain
    __delslice__ = complain
    __iadd__ = complain
    __imul__ = complain
    __setitem__ = complain
    __setslice__ = complain
    append = complain
    extend = complain
    insert = complain
    pop = complain
    remove = complain
    sort = complain
    reverse = complain


class DictWrapper(Dict[str, VT], Generic[VT]):
    """
    Wraps accesses to a dictionary so that certain values (those starting with
    the specified prefix) are passed through a function before being returned.
    The prefix is removed before looking up the real value.

    Used by the SQL construction code to ensure that values are correctly
    quoted before being used.
    """
    def __init__(self, data, func, prefix):
        # type: (Mapping[str, VT], Callable[[VT], VT], str) -> None
        super(DictWrapper, self).__init__(data)
        self.func = func
        self.prefix = prefix

    def __getitem__(self, key):
        # type: (str) -> VT
        """
        Retrieves the real value after stripping the prefix string (if
        present). If the prefix is present, pass the value through self.func
        before returning, otherwise return the raw value.
        """
        if key.startswith(self.prefix):
            use_func = True
            key = key[len(self.prefix):]
        else:
            use_func = False
        value = super(DictWrapper, self).__getitem__(key)
        if use_func:
            return self.func(value)
        return value
