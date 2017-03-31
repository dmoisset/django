"""
Base file upload handler classes, and the built-in concrete subclasses
"""

from __future__ import unicode_literals

from io import BytesIO
from typing import Any, Dict, IO, Optional, Tuple, TYPE_CHECKING

from django.conf import settings
from django.core.files.uploadedfile import (
    UploadedFile, InMemoryUploadedFile, TemporaryUploadedFile,
)
from django.utils.datastructures import MultiValueDict
from django.utils.encoding import python_2_unicode_compatible
from django.utils.module_loading import import_string
if TYPE_CHECKING:
    from django.http.request import HttpRequest, QueryDict

__all__ = [
    'UploadFileException', 'StopUpload', 'SkipFile', 'FileUploadHandler',
    'TemporaryFileUploadHandler', 'MemoryFileUploadHandler', 'load_handler',
    'StopFutureHandlers'
]


class UploadFileException(Exception):
    """
    Any error having to do with uploading files.
    """
    pass


@python_2_unicode_compatible
class StopUpload(UploadFileException):
    """
    This exception is raised when an upload must abort.
    """
    def __init__(self, connection_reset: bool=False) -> None:
        """
        If ``connection_reset`` is ``True``, Django knows will halt the upload
        without consuming the rest of the upload. This will cause the browser to
        show a "connection reset" error.
        """
        self.connection_reset = connection_reset

    def __str__(self) -> str:
        if self.connection_reset:
            return 'StopUpload: Halt current upload.'
        else:
            return 'StopUpload: Consume request data, then halt.'


class SkipFile(UploadFileException):
    """
    This exception is raised by an upload handler that wants to skip a given file.
    """
    pass


class StopFutureHandlers(UploadFileException):
    """
    Upload handers that have handled a file and do not want future handlers to
    run should raise this exception instead of returning None.
    """
    pass


class FileUploadHandler(object):
    """
    Base class for streaming upload handlers.
    """
    chunk_size = 64 * 2 ** 10  # : The default chunk size is 64 KB.

    def __init__(self, request: 'HttpRequest'=None) -> None:
        self.file_name = None  # type: Optional[str]
        self.content_type = None  # type: Optional[str]
        self.content_length = None  # type: Optional[int]
        self.charset = None  # type: Optional[str]
        self.content_type_extra = None  # type: Optional[Dict[str, str]]
        self.request = request

    def handle_raw_input(self, input_data: IO[bytes], META: Dict[str, str], content_length: int,
                         boundary: str, encoding: str=None) -> Optional[Tuple['QueryDict', MultiValueDict[str, UploadedFile]]]:
        """
        Handle the raw input from the client.

        Parameters:

            :input_data:
                An object that supports reading via .read().
            :META:
                ``request.META``.
            :content_length:
                The (integer) value of the Content-Length header from the
                client.
            :boundary: The boundary from the Content-Type header. Be sure to
                prepend two '--'.
        """
        pass

    def new_file(self, field_name: str, file_name: str, content_type: str,
                 content_length: Optional[int], charset: str=None,
                 content_type_extra: Dict[str, str]=None) -> None:
        """
        Signal that a new file has been started.

        Warning: As with any data from the client, you should not trust
        content_length (and sometimes won't even get it).
        """
        self.field_name = field_name
        self.file_name = file_name
        self.content_type = content_type
        self.content_length = content_length
        self.charset = charset
        self.content_type_extra = content_type_extra

    def receive_data_chunk(self, raw_data: bytes, start: int) -> Optional[bytes]:
        """
        Receive data from the streamed upload parser. ``start`` is the position
        in the file of the chunk.
        """
        raise NotImplementedError('subclasses of FileUploadHandler must provide a receive_data_chunk() method')

    def file_complete(self, file_size: int) -> Optional[UploadedFile]:
        """
        Signal that a file has completed. File size corresponds to the actual
        size accumulated by all the chunks.

        Subclasses should return a valid ``UploadedFile`` object.
        """
        raise NotImplementedError('subclasses of FileUploadHandler must provide a file_complete() method')

    def upload_complete(self) -> None:
        """
        Signal that the upload is complete. Subclasses should perform cleanup
        that is necessary for this handler.
        """
        pass


class TemporaryFileUploadHandler(FileUploadHandler):
    """
    Upload handler that streams data into a temporary file.
    """
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super(TemporaryFileUploadHandler, self).__init__(*args, **kwargs)

    def new_file(self, *args: Any, **kwargs: Any) -> None:
        """
        Create the file object to append to as data is coming in.
        """
        super(TemporaryFileUploadHandler, self).new_file(*args, **kwargs)
        self.file = TemporaryUploadedFile(self.file_name, self.content_type, 0, self.charset, self.content_type_extra)  # type: ignore  # at this point new_file should have set non-null values to the fields

    def receive_data_chunk(self, raw_data: bytes, start: int) -> Optional[bytes]:
        self.file.write(raw_data)
        return None

    def file_complete(self, file_size: int) -> Optional[UploadedFile]:
        self.file.seek(0)
        self.file.size = file_size
        return self.file


class MemoryFileUploadHandler(FileUploadHandler):
    """
    File upload handler to stream uploads into memory (used for small files).
    """

    def handle_raw_input(self, input_data: IO[bytes], META: Dict[str, str], content_length: int,
                         boundary: str, encoding: str=None) -> Optional[Tuple['QueryDict', MultiValueDict[str, UploadedFile]]]:
        """
        Use the content_length to signal whether or not this handler should be in use.
        """
        # Check the content-length header to see if we should
        # If the post is too large, we cannot use the Memory handler.
        if content_length > settings.FILE_UPLOAD_MAX_MEMORY_SIZE:
            self.activated = False
        else:
            self.activated = True
        return None

    def new_file(self, *args: Any, **kwargs: Any) -> None:
        super(MemoryFileUploadHandler, self).new_file(*args, **kwargs)
        if self.activated:
            self.file = BytesIO()
            raise StopFutureHandlers()

    def receive_data_chunk(self, raw_data: bytes, start: int) -> Optional[bytes]:
        """
        Add the data to the BytesIO file.
        """
        if self.activated:
            self.file.write(raw_data)
            return None
        else:
            return raw_data

    def file_complete(self, file_size: int) -> Optional[UploadedFile]:
        """
        Return a file object if we're activated.
        """
        if not self.activated:
            return None

        self.file.seek(0)
        return InMemoryUploadedFile(  # type: ignore  # self.file_name should not be None here
            file=self.file,
            field_name=self.field_name,
            name=self.file_name,
            content_type=self.content_type,
            size=file_size,
            charset=self.charset,
            content_type_extra=self.content_type_extra
        )


def load_handler(path: str, *args: Any, **kwargs: Any) -> FileUploadHandler:
    """
    Given a path to a handler, return an instance of that handler.

    E.g.::
        >>> from django.http import HttpRequest
        >>> request = HttpRequest()
        >>> load_handler('django.core.files.uploadhandler.TemporaryFileUploadHandler', request)
        <TemporaryFileUploadHandler object at 0x...>
    """
    return import_string(path)(*args, **kwargs)
