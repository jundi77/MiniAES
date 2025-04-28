from abc import ABC, abstractmethod
from .GeneralOperation import GeneralOperation
from .KeyOperation import KeyOperation
from ..data.PlaintextBase import PlaintextBase
from ..data.CiphertextBase import CiphertextBase
from ..utils.Bit import Bit
from ..logs.LogManager import LogManager

class EncryptionOperationBase(ABC):
    def __init__(self, plaintext: PlaintextBase, key: KeyOperation, ciphertext: CiphertextBase):
        # super().__init__()
        self._ciphertext = ciphertext
        self._plaintext = plaintext
        self._key = key
        self._logger = None

    def set_logger(self, logger: LogManager):
        self._logger: LogManager = logger

    def log(self, event: str):
        if self._logger is not None:
            self._logger.push(event)

    @staticmethod
    def _shift_rows(data: int) -> int:
        """
        data is in 2 bytes (16 bit).
        each cell in the state array is a nibble (4 bit).

        Using NIST FIPS 197, AES shift row.
        first row not moving, second row move
        to the left once.
            -----------    \   -----------
            |s0,0|s0,1|  ---\  |s0,0|s0,1|
            |s1,0|s1,1|  ---/  |s1,1|s1,0|
            -----------    /   -----------
        """
        # 1st row is already okay
        shifted = data

        # WACKY but *et_nth_bit is tested, so...
        shifted = Bit.set_nth_bit(4, Bit.get_nth_bit(12, data), shifted)
        shifted = Bit.set_nth_bit(5, Bit.get_nth_bit(13, data), shifted)
        shifted = Bit.set_nth_bit(6, Bit.get_nth_bit(14, data), shifted)
        shifted = Bit.set_nth_bit(7, Bit.get_nth_bit(15, data), shifted)

        shifted = Bit.set_nth_bit(12, Bit.get_nth_bit(4, data), shifted)
        shifted = Bit.set_nth_bit(13, Bit.get_nth_bit(5, data), shifted)
        shifted = Bit.set_nth_bit(14, Bit.get_nth_bit(6, data), shifted)
        shifted = Bit.set_nth_bit(15, Bit.get_nth_bit(7, data), shifted)

        return shifted

    @staticmethod
    def _mix_columns(data: int) -> int:
        """
        data is in 2 bytes (16 bit).
        each cell in the state array is a nibble (4 bit).

        not done with bit mode because i need clarity,
        unfamiliar with this whole GF(2^4) thingy.
        """
        prev_lsbytes, prev_msbytes = Bit.split_2byte(data)

        # here, each nibble is it's own column
        n = [0, 0, 0, 0]
        n[0], n[1] = Bit.split_byte(prev_lsbytes)
        n[2], n[3] = Bit.split_byte(prev_msbytes)
        mixed = [0, 0, 0, 0]
        mixed[0] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[0][0], n[0]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[0][1], n[1]
        )

        mixed[1] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[1][0], n[0]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[1][1], n[1]
        )

        mixed[2] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[0][0], n[2]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[0][1], n[3]
        )

        mixed[3] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[1][0], n[2]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._MDS[1][1], n[3]
        )

        return Bit.prepend_nibble(mixed[0], Bit.prepend_nibble(mixed[1], Bit.prepend_nibble(mixed[2], mixed[3])))

    def _do_rounds(self, data: int) -> int:
        """
        data is in 2 bytes (16 bit).
        each cell in the state array is a nibble (4 bit).

        Using NIST FIPS 197 as reference, the input, state, and output
        representation is as follows:

            input bit is:
                ---------
                |in0|in2|
                |in1|in3|
                ---------

            state array:
                -----------
                |s0,0|s0,1|
                |s1,0|s1,1|
                -----------

            output bits:
                -----------
                |out0|out2|
                |out1|out3|
                -----------
        """
#         print(("enc round data is", hex(data), bin(data)))
        self.log(f"Encryption rounds will start for piece: {hex(data)}")

        data ^= self._key.get_round_key(0)
        # print(("enc preround data is", hex(data), bin(data)))
        self.log(f"Pre-round, xor data with the key: {hex(data)}")

        ############## 1st round ##############
        data = GeneralOperation._sub_nibbles(data, 2)
        # print(("1st round sub", hex(data), bin(data)))
        self.log(f"1st round, sub nibbles: {hex(data)}")

        data = EncryptionOperationBase._shift_rows(data)
        # print(("1st round shift", hex(data), bin(data)))
        self.log(f"1st round, shift rows: {hex(data)}")

        data = EncryptionOperationBase._mix_columns(data)
        # print(("1st round mix", hex(data), bin(data)))
        self.log(f"1st round, mix columns: {hex(data)}")

        data ^= self._key.get_round_key(1)
        # print(("1st round xor key", hex(data), bin(data)))
        self.log(f"1st round, xor with round key: {hex(data)}")

        ############## 2nd round ##############
        data = GeneralOperation._sub_nibbles(data, 2)
        # print(("2nd round sub", hex(data), bin(data)))
        self.log(f"2nd round, sub nibbles: {hex(data)}")

        data = EncryptionOperationBase._shift_rows(data)
        # print(("2nd round shift", hex(data), bin(data)))
        self.log(f"2nd round, shift rows: {hex(data)}")

        data = EncryptionOperationBase._mix_columns(data)
        # print(("2nd round mix", hex(data), bin(data)))
        self.log(f"2nd round, mix columns: {hex(data)}")

        data ^= self._key.get_round_key(2)
        # print(("2nd round xor key", hex(data), bin(data)))
        self.log(f"2nd round, xor with round key: {hex(data)}")

        ############## 3rd round ##############
        data = GeneralOperation._sub_nibbles(data, 2)
        # print(("3rd round sub", hex(data), bin(data)))
        self.log(f"3rd round, sub nibbles: {hex(data)}")

        data = EncryptionOperationBase._shift_rows(data)
        # print(("3rd round shift", hex(data), bin(data)))
        self.log(f"3rd round, shift rows: {hex(data)}")

        data ^= self._key.get_round_key(3)
        # print(("3rd round xor key", hex(data), bin(data)))
        self.log(f"3rd round, xor with round key: {hex(data)}")

        return data

    @abstractmethod
    def encrypt(self) -> None:
        pass
