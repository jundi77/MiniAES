from abc import ABC, abstractmethod
from .GeneralOperation import GeneralOperation
from .KeyOperation import KeyOperation
from ..data.CiphertextBase import CiphertextBase
from ..data.PlaintextBase import PlaintextBase
from ..utils.Bit import Bit
from ..logs.LogManager import LogManager

class DecryptionOperationBase(ABC):
    def __init__(self, ciphertext: CiphertextBase, key: KeyOperation, plaintext: PlaintextBase):
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
    def _inv_shift_rows(data: int) -> int:
        """
        data is in 2 bytes (16 bit).
        each cell in the state array is a nibble (4 bit).

        Using NIST FIPS 197, AES shift row.
        first row not moving, second row move
        to the right once.
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
    def _inv_mix_columns(data: int) -> int:
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

        re_mixed = [0, 0, 0, 0] # heh... re-mixed... funny... :D
        re_mixed[0] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[0][0], n[0]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[0][1], n[1]
        )

        re_mixed[1] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[1][0], n[0]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[1][1], n[1]
        )

        re_mixed[2] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[0][0], n[2]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[0][1], n[3]
        )

        re_mixed[3] = GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[1][0], n[2]
        ) ^ GeneralOperation._FIELD_OPS.Multiply(
            GeneralOperation._INV_MDS[1][1], n[3]
        )

        return Bit.prepend_nibble(re_mixed[0], Bit.prepend_nibble(re_mixed[1], Bit.prepend_nibble(re_mixed[2], re_mixed[3])))

    def _do_inv_rounds(self, data: int) -> int:
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
        self.log(f"Decryption rounds will start for piece: {hex(data)}")

        # print(("dec round data is", hex(data), bin(data)))
        data ^= self._key.get_round_key(3)
        # print(("dec preround data is", hex(data), bin(data)))
        self.log(f"Pre-round, xor data with the last (3rd) round key: {hex(data)}")

        ############## 1st round ##############
        data = DecryptionOperationBase._inv_shift_rows(data)
        # print(("1st round shift", hex(data), bin(data)))
        self.log(f"1st round, inverse shift rows: {hex(data)}")

        data = GeneralOperation._inv_sub_nibbles(data, 2)
        # print(("1st round sub", hex(data), bin(data)))
        self.log(f"1st round, inverse sub nibble: {hex(data)}")

        data ^= self._key.get_round_key(2)
        # print(("1st round xor key", hex(data), bin(data)))
        self.log(f"1st round, xor with 2nd round key: {hex(data)}")

        data = DecryptionOperationBase._inv_mix_columns(data)
        # print(("1st round mix", hex(data), bin(data)))
        self.log(f"1st round, inverse mix columns: {hex(data)}")

        ############## 2nd round ##############
        data = DecryptionOperationBase._inv_shift_rows(data)
        # print(("2nd round shift", hex(data), bin(data)))
        self.log(f"2nd round, inverse shift rows: {hex(data)}")

        data = GeneralOperation._inv_sub_nibbles(data, 2)
        # print(("2nd round sub", hex(data), bin(data)))
        self.log(f"2nd round, inverse sub nibble: {hex(data)}")

        data ^= self._key.get_round_key(1)
        # print(("2nd round xor key", hex(data), bin(data)))
        self.log(f"2nd round, xor with 1st round key: {hex(data)}")

        data = DecryptionOperationBase._inv_mix_columns(data)
        # print(("2nd round mix", hex(data), bin(data)))
        self.log(f"2nd round, inverse mix columns: {hex(data)}")

        ############## 3rd round ##############
        data = DecryptionOperationBase._inv_shift_rows(data)
        # print(("3rd round shift", hex(data), bin(data)))
        self.log(f"3rd round, inverse shift rows: {hex(data)}")

        data = GeneralOperation._inv_sub_nibbles(data, 2)
        # print(("3rd round sub", hex(data), bin(data)))
        self.log(f"3rd round, inverse sub nibble: {hex(data)}")

        data ^= self._key.get_round_key(0)
        # print(("3rd round xor key", hex(data), bin(data)))
        self.log(f"3rd round, xor with 0th round key: {hex(data)}")

        return data

    @abstractmethod
    def decrypt(self) -> bytes:
        pass
