from abc import abstractmethod
from typing import Final, Literal
from .Readable import Readable
from .Writable import Writable
from ..io.files.FileReaderInterface import FileReaderInterface
from ..io.files.FileWriterInterface import FileWriterInterface

class RWPermissionOnEncOrDec(Readable, Writable):
    VALID_MODE: Final[list[str]] = ["enc", "dec"]

    def __init__(self, file_io: FileReaderInterface | FileWriterInterface, mode: Literal["enc", "dec"]):
        super().__init__()

        if mode not in self.VALID_MODE:
            raise ValueError(f"Invalid mode ({mode}), expecting one of {self.VALID_MODE}")

        self._file_io = file_io
        self.__mode = mode

    def __encryption_mode(self) -> bool:
        return self.__mode == "enc"

    def __decryption_mode(self) -> bool:
        return self.__mode == "dec"

    def _abort_if_decrypting(self):
        if self.__decryption_mode():
            raise PermissionError(f"{self.__class__.__name__} will be used for decryption: reading is not allowed.")

    def _abort_if_encrypting(self):
        if self.__encryption_mode():
            raise PermissionError(f"{self.__class__.__name__} will be used for encryption: writing is not allowed.")

    def close(self) -> None:
        self._file_io.close()

    # @abstractmethod
    # def read_data(self, close: bool = False) -> None:
    #     if self.__decryption_mode():
    #         raise PermissionError(f"{self.__class__.__name__} is used in encryption: reading is not allowed.")

    # @abstractmethod
    # def write_data(self, data: bytes | str | int, close: bool = False) -> None:
    #     if self.__encryption_mode():
    #         raise PermissionError(f"{self.__class__.__name__} is used in decryption: writing is not allowed.")
