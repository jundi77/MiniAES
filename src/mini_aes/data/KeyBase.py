from abc import abstractmethod
from typing import Tuple
from .Readable import Readable
from ..io.files.FileReaderInterface import FileReaderInterface

class KeyBase(Readable):
    def __init__(self, file_io: FileReaderInterface):
        super().__init__()
        self._file_io = file_io

    @abstractmethod
    def ended(self) -> bool:
        pass

    def close(self) -> None:
        self._file_io.close()

    @abstractmethod
    def read_data(self, close: bool = False) -> Tuple[int, int] | Tuple[None, int]:
        super().read_data(close)
        """
        Bufer is 2 bytes.
        Key in this project has to be 2 bytes.

        Use self._file_io. FileReaderInterface might use binary
        or text file mode. Account Iterator's for either of them
        and convert them in this function to int.

        None if EOF.

        Use little config for int.from_bytes
        (if file is b'\x10\x00', the binary is 0b1000)
        """
        pass
