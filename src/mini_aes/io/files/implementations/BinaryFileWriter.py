from ..FileWriterInterface import FileWriterInterface
from io import BufferedWriter, BytesIO

class BinaryFileWriter(FileWriterInterface):
    def __init__(self, filepath: str=None, file_io: BytesIO | BufferedWriter=None):
        self.__filepath = filepath
        self.__file = file_io

    def __open(self):
        if self.__file is None:
            self.__file = open(self.__filepath, 'wb')

    def __close(self):
        if isinstance(self.__file, BufferedWriter) and not self.__file.closed:
            self.__file.close()

    def __del__(self):
        self.__close()

    def close(self):
        self.__close()

    def write(self, data: bytes | str, close: bool = False) -> None:
        if self.__file is None:
            self.__open()

        if self.__file.closed:
            raise IOError("Writing to a closed file.")

        if not self.__file.writable():
            raise IOError("Writing to a file that is not for writing.")

        if isinstance(data, str):
            # implicitly convert to bytes
            data = data.encode()

        self.__file.write(data)

        if close:
            self.__close()
