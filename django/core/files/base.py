from __future__ import unicode_literals

import os
from io import BytesIO, StringIO, UnsupportedOperation
from typing import Any, Iterator, Optional, Union

from django.core.files.utils import FileProxyMixin
from django.utils import six
from django.utils.encoding import (
    force_bytes, force_str, python_2_unicode_compatible, smart_text,
)


@python_2_unicode_compatible
class File(FileProxyMixin):
    DEFAULT_CHUNK_SIZE = 64 * 2 ** 10

    def __init__(self, file, name=None):
        # type: (Any, Optional[str]) -> None
        self.file = file
        if name is None:
            name = getattr(file, 'name', None)
        self.name = name
        if hasattr(file, 'mode'):
            self.mode = file.mode

    def __str__(self):
        # type: () -> str
        return smart_text(self.name or '')

    def __repr__(self):
        # type: () -> str
        return force_str("<%s: %s>" % (self.__class__.__name__, self or "None"))

    def __bool__(self):
        # type: () -> bool
        return bool(self.name)

    def __nonzero__(self):
        # type: () -> bool
        # Python 2 compatibility
        return type(self).__bool__(self)

    def __len__(self):
        # type: () -> int
        return self.size

    def _get_size_from_underlying_file(self):
        # type: () -> int
        if hasattr(self.file, 'size'):
            return self.file.size
        if hasattr(self.file, 'name'):
            try:
                return os.path.getsize(self.file.name)
            except (OSError, TypeError):
                pass
        if hasattr(self.file, 'tell') and hasattr(self.file, 'seek'):
            pos = self.file.tell()
            self.file.seek(0, os.SEEK_END)
            size = self.file.tell()
            self.file.seek(pos)
            return size
        raise AttributeError("Unable to determine the file's size.")

    @property
    def size(self):
        # type: () -> int
        if hasattr(self, '_size'):
            return self._size  # type: ignore
        self._size = self._get_size_from_underlying_file()
        return self._size

    @size.setter
    def size(self, size):
        # type: (int) -> None
        self._size = size

    @property
    def closed(self):
        # type: () -> bool
        return not self.file or self.file.closed

    def chunks(self, chunk_size=None):
        # type: (Optional[int]) -> Iterator[bytes]
        """
        Read the file and yield chunks of ``chunk_size`` bytes (defaults to
        ``UploadedFile.DEFAULT_CHUNK_SIZE``).
        """
        if not chunk_size:
            chunk_size = self.DEFAULT_CHUNK_SIZE

        try:
            self.seek(0)
        except (AttributeError, UnsupportedOperation):
            pass

        while True:
            data = self.read(chunk_size)
            if not data:
                break
            yield data

    def multiple_chunks(self, chunk_size=None):
        # type: (Optional[int]) -> bool
        """
        Returns ``True`` if you can expect multiple chunks.

        NB: If a particular file representation is in memory, subclasses should
        always return ``False`` -- there's no good reason to read from memory in
        chunks.
        """
        if not chunk_size:
            chunk_size = self.DEFAULT_CHUNK_SIZE
        assert isinstance(chunk_size, int)
        return self.size > chunk_size

    def __iter__(self):
        # type: () -> Iterator[bytes]
        # Iterate over this file-like object by newlines
        buffer_ = None
        for chunk in self.chunks():
            for line in chunk.splitlines(True):
                if buffer_:
                    if endswith_cr(buffer_) and not equals_lf(line):
                        # Line split after a \r newline; yield buffer_.
                        yield buffer_
                        # Continue with line.
                    else:
                        # Line either split without a newline (line
                        # continues after buffer_) or with \r\n
                        # newline (line == b'\n').
                        line = buffer_ + line
                    # buffer_ handled, clear it.
                    buffer_ = None

                # If this is the end of a \n or \r\n line, yield.
                if endswith_lf(line):
                    yield line
                else:
                    buffer_ = line

        if buffer_ is not None:
            yield buffer_

    def __enter__(self):
        # type: () -> File
        return self

    def __exit__(self, exc_type, exc_value, tb):
        # type: (Optional[type], Optional[BaseException], Any) -> bool
        self.close()
        return False

    def open(self, mode=None):
        # type: (Optional[str]) -> None
        if not self.closed:
            self.seek(0)
        elif self.name and os.path.exists(self.name):
            self.file = open(self.name, mode or self.mode)
        else:
            raise ValueError("The file cannot be reopened.")

    def close(self):
        # type: () -> None
        self.file.close()


@python_2_unicode_compatible
class ContentFile(File):
    """
    A File-like object that takes just raw content, rather than an actual file.
    """
    def __init__(self, content, name=None):
        # type: (Union[str, bytes], Optional[str]) -> None
        if six.PY3:
            stream_class = StringIO if isinstance(content, six.text_type) else BytesIO
        else:
            stream_class = BytesIO
            content = force_bytes(content)
        super(ContentFile, self).__init__(stream_class(content), name=name)
        self.size = len(content)

    def __str__(self):
        # type: () -> str
        return 'Raw content'

    def __bool__(self):
        # type: () -> bool
        return True

    def __nonzero__(self):
        # type: () -> bool
        return type(self).__bool__(self)

    def open(self, mode=None):
        # type: (Optional[str]) -> None
        self.seek(0)

    def close(self):
        # type: () -> None
        pass


def endswith_cr(line):
    # type: (Union[str, bytes]) -> bool
    """
    Return True if line (a text or byte string) ends with '\r'.
    """
    return line.endswith('\r' if isinstance(line, six.text_type) else b'\r')  # type: ignore


def endswith_lf(line):
    # type: (Union[str, bytes]) -> bool
    """
    Return True if line (a text or byte string) ends with '\n'.
    """
    return line.endswith('\n' if isinstance(line, six.text_type) else b'\n')  # type: ignore


def equals_lf(line):
    # type: (Union[str, bytes]) -> bool
    """
    Return True if line (a text or byte string) equals '\n'.
    """
    return line == ('\n' if isinstance(line, six.text_type) else b'\n')
