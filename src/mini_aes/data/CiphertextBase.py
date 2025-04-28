from abc import abstractmethod
from typing import Literal, Tuple
from .RWPermissionOnEncOrDec import RWPermissionOnEncOrDec
from ..io.files.FileReaderInterface import FileReaderInterface
from ..io.files.FileWriterInterface import FileWriterInterface

class CiphertextBase(RWPermissionOnEncOrDec):
    def __init__(self, file_io: FileReaderInterface | FileWriterInterface, mode: Literal["enc", "dec"]):
        super().__init__(file_io, mode)

    @abstractmethod
    def ended(self) -> bool:
        pass

    @abstractmethod
    def read_data(self, close: bool = False) -> Tuple[int, int] | Tuple[None, int]:
        """
        Bufer is 2 bytes.

        Use self._file_io. FileReaderInterface might use binary
        or text file mode. Account for Iterator's for either of them
        and convert them in this function to int.

        None if EOF.

        Use little config for int.from_bytes
        (if file is b'\x10\x00', the binary is 0b1000)
        """
        super().read_data(close)
        self._abort_if_encrypting()

    @abstractmethod
    def write_data(self, data: bytes | str | int, close: bool = False) -> None:
        """
        data must be 2 bytes.

        Use self._file_io. FileWriterInterface can accept bytes, or
        str, or int. If io is in str mode and the data cannot be decoded on the
        underlying classes, it will raise some exception related to encoding.

        Use (int).to_bytes(2, 'little') if wanting to convert
        the int to 2 byte.
        """
        super().write_data(data, close)
        self._abort_if_decrypting()
