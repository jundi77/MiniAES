from abc import abstractmethod
from typing import Final
from .GeneralOperation import GeneralOperation
from ..data.KeyBase import KeyBase
from ..utils.Bit import Bit

class KeyOperation(GeneralOperation):
    _RCON: Final[dict[int, int]] = {1: 0b1}

    def __init__(self, key: KeyBase):
        """
        initial key is 2 bytes, 4 nibble, 8 bit.
        """
        super().__init__()
        initial_key, length = key.read_data()
        Bit.check_2bytes(initial_key)
        if length < 2:
            raise ValueError("Key has to be 2 bytes.")

        self._ROUND_KEY: Final[dict[int, int]] = {
            0: initial_key
        }

    @staticmethod
    def _rot_byte(data: int) -> int:
        """
        data is a byte.
        rotation is per nibble.
        """
        lsn = data & 0b1111 # n for nibble, least significant nibble
        data >>= 4 # remove lsn

        return data ^ (lsn << 4)

    @staticmethod
    def _get_round_constant(nth: int) -> int:
        """
        Way of generating round constant is got from:
        (https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf)
        in quote:
            The round constant for the ith round is denoted Rcon[i].
            Since, by specification, the three rightmost bytes of the round
            constant are zero, we can write it as shown below. The left hand
            side of the equation below stands for the round constant to be
            used in the ith round. The right hand side of the equation says
            that the rightmost three bytes of the round constant are zero.
                Rcon[i] = (RC[i], 0x00, 0x00, 0x00)
            The only non-zero byte in the round constants, RC[i], obeys
            the following recursion:
                RC[1] = 0x01
                RC[j] = 0x02 x RC[j - 1]

        Remember that we are doing this in GF(2^4).
        """
        if nth < 1:
            raise ValueError("Expanding round is starting from 1.")

        if nth in KeyOperation._RCON:
            return KeyOperation._RCON[nth]

        KeyOperation._RCON[nth] = GeneralOperation._FIELD_OPS.Multiply(
            2,
            KeyOperation._get_round_constant(nth-1)
        )

        return KeyOperation._RCON[nth]

    def get_round_key(self, nth: int) -> int:
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

        in there, key is word. here, it is byte:
            -------
            |b0|b1|
            -------
        """
        if nth < 0:
            raise ValueError("Key round is starting from 0.")

        if nth in self._ROUND_KEY:
            # print((f"key for round {nth} is prefilled", hex(self._ROUND_KEY[nth])))
            return self._ROUND_KEY[nth]

        prev_key = self.get_round_key(nth - 1)
        prev_key_lsbyte, prev_key_msbyte = Bit.split_2byte(prev_key)

        """
            wi+5 = wi+4 ⊗ wi+1 (1)
            wi+6 = wi+5 ⊗ wi+2 (2)
            wi+7 = wi+6 ⊗ wi+3 (3)
        while
            wi+4 = wi ⊗ g(wi+3) (4)
        where g function is:
            - Perform a one-byte left circular
            rotation on the argument 4-byte word.
            - Perform a byte substitution for each
            byte of the word returned by the previous
            step by using the same 16x16 lookup table
            as used in the SubBytes step of the
            encryption rounds.
            - XOR the bytes obtained from the previous
            step with what is known as a round constant.
            The round constant is a word whose three
            rightmost bytes are always zero. Therefore,
            XOR'ing with the round constant amounts to
            XOR'ing with just its leftmost byte.

        remember that instead of word, this key works
        with 2 byte.
        """
        b0 = GeneralOperation._sub_nibbles(
            KeyOperation._rot_byte(prev_key_msbyte),
            1
        ) ^ KeyOperation._get_round_constant(nth) ^ prev_key_lsbyte
        b1 = b0 ^ prev_key_msbyte
        self._ROUND_KEY[nth] = Bit.prepend_byte(b0, b1)
        # print((f"key for round {nth}", hex(self._ROUND_KEY[nth])))

        return self._ROUND_KEY[nth]
