from ..FileReaderInterface import FileReaderInterface
from io import BufferedReader, BytesIO
from typing import Iterator, Tuple

class BinaryFileReader(FileReaderInterface):
    def __init__(self, filepath: str=None, file_io: BytesIO | BufferedReader=None):
        self.__filepath = filepath
        self.__file = file_io

    def __open(self):
        if self.__file is None:
            self.__file: BufferedReader = open(self.__filepath, 'rb')

    def __close(self):
        if isinstance(self.__file, BufferedReader) and not self.__file.closed:
            self.__file.close()

    def __del__(self):
        self.__close()

    def close(self):
        self.__close()

    def read(self, buffer_bytes: int=2, close: bool=False) -> Tuple[bytes, bool]:
        # print("binary file read")
        if self.__file is None:
            self.__open()

        if self.__file.closed:
            raise IOError("Reading from a closed file.")

        if not self.__file.readable():
            raise IOError("Reading from a file that is not for reading.")

        # print(("binary file read pos", self.__file.tell()))
        current = self.__file.read(2)
        after = self.__file.read(2)
        self.__file.seek(-2, 1)

        if after == b'':
            return current, True
        else:
            return current, False
