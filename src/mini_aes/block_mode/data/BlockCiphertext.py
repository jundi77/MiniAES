from typing import Literal, Tuple
from ...utils.Bit import Bit
from ...data.CiphertextBase import CiphertextBase
from ...io.files.FileReaderInterface import FileReaderInterface
from ...io.files.FileWriterInterface import FileWriterInterface

class BlockCiphertext(CiphertextBase):
    def __init__(self, file_io: FileReaderInterface | FileWriterInterface, mode: Literal["enc", "dec"]):
        super().__init__(file_io, mode)
        self._ended = False

    def ended(self) -> bool:
        return self._ended

    def read_data(self) -> Tuple[int, int] | Tuple[None, int]:
        # print("ciphertext read")
        super().read_data()

        if self.ended():
            return None, 0

        data, stop = self._file_io.read()
        if stop:
            self._ended = True

        if isinstance(data, str):
            data: bytes = data.encode()

        return int.from_bytes(data, 'little'), len(data)

    def write_data(self, data: bytes | str | int, close: bool = False) -> None:
        # print("ciphertext write")
        super().write_data(data, close)

        if isinstance(data, int):
            # TODO Bug hunt
            # found ze bug
            # ciphertext always write in 2 bytes
            # length = max(1, (data.bit_length() + 7) // 8)
            length = 2
            data = data.to_bytes(length, 'little') # +7 so that there is always 0xXX space for a value
                                                                         # e.g. 0b1 is 1 bit length, +7 is 8 bit length.

        self._file_io.write(data, close)
