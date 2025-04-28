from random import randint
from typing import Tuple

class Bit():
    @staticmethod
    def check_bit(num: int) -> None:
        """
        this function takes int and check if
        it's within 1 byte range.
        if it is not, assertion error.
        """
        if num < 0x00:
            raise ValueError("Cannot accept negative value.")

        if num > 0x1:
            raise OverflowError("Given number is too big to be 1 bit.")

    @staticmethod
    def check_2bytes(num: int) -> None:
        """
        this function takes int and check if
        it's within 1 byte range.
        if it is not, assertion error.
        """
        if num < 0x00:
            raise ValueError("Cannot accept negative value.")

        if num > 0xFFFF:
            raise OverflowError("Given number is too big to be 2 bytes.")

    @staticmethod
    def check_byte(num: int) -> None:
        """
        this function takes int and check if
        it's within 1 byte range.
        if it is not, assertion error.
        """
        if num < 0x00:
            raise ValueError("Cannot accept negative value.")

        if num > 0xFF:
            raise OverflowError("Given number is too big to be 1 byte.")

    @staticmethod
    def check_nibble(num: int) -> None:
        """
        this function takes int and check if
        it's within half byte range.
        if it is not, assertion error.
        """
        if num < 0x00:
            raise ValueError("Cannot accept negative value.")

        if num > 0xF:
            raise OverflowError("Given number is too big to be half byte.")

    @staticmethod
    def split_2byte(piece: int) -> Tuple[int, int]:
        """
        this function takes piece that has max value of 2 bytes,
        but defined as int because each member of bytes
        in python is defined as int. this also means
        the function may take value bigger than
        2 bytes.

        return value is splitted byte (lsb, msb):
            (half byte, half byte)
            or
            (4 bit, 4 bit)
        """
        Bit.check_2bytes(piece)

        # least significant byte
        lsb = piece & 0b11111111

        # most significant byte
        msb = (piece >> 8) & 0b11111111

        return lsb, msb

    @staticmethod
    def split_byte(piece: int) -> Tuple[int, int]:
        """
        this function actually takes single byte, but
        defined as int because each member of bytes
        in python is defined as int. this also means
        the function may take value bigger than
        255 (0xFF) which is problematic.

        return value is splitted byte (lsb, msb):
            (half byte, half byte)
            or
            (4 bit, 4 bit)
        """
        Bit.check_byte(piece)

        # least significant half bytes
        lsb = piece & 0b1111

        # most significant half bytes
        msb = (piece >> 4) & 0b1111

        return lsb, msb

    @staticmethod
    def prepend_bit(_bit: int, value: int) -> int:
        Bit.check_bit(_bit)
        return (value << 1) ^ _bit

    @staticmethod
    def prepend_nibble(nibble: int, value: int) -> int:
        Bit.check_nibble(nibble)
        return (value << 4) ^ nibble

    @staticmethod
    def prepend_byte(_byte: int, value: int) -> int:
        Bit.check_byte(_byte)
        return (value << 8) ^ _byte

    @staticmethod
    def get_nth_bit(nth: int, piece: int) -> int:
        """
        piece argument are single byte, but
        defined as int because each member of bytes
        in python is defined as int. this also means
        the function may take value bigger than
        255 (0xFF) which is problematic.

        return nth bit, 0 based index.
        """
        if nth < 0:
            raise ValueError("Does not support negative indexes.")

        mask = 0b1 << nth

        return (piece & mask) >> nth

    @staticmethod
    def set_nth_bit(nth: int, val: int, piece: int) -> int:
        """
        piece and val takes single byte, but
        defined as int because each member of bytes
        in python is defined as int. this also means
        the function may take value bigger than
        255 (0xFF) which is problematic.

        set nth bit, 0 based index.
        """
        Bit.check_bit(val)

        if nth < 0:
            raise ValueError("Does not support negative indexes.")

        # clear the bit
        piece &= ~(0b1 << nth)

        # set the bit
        piece |= val << nth

        return piece

    @staticmethod
    def list_to_2bytes(val_vtx: list) -> int:
        val = 0b0
        for i in range(4):
            Bit.check_nibble(val_vtx[i])
            val ^= val_vtx[i] << (i * 4)

        return val

    @staticmethod
    def list_from_2bytes(val: int) -> list:
        """
        2 bytes will be split to 4 nibble.
        """
        vtx = []
        nib_mask = 0b1111
        for _ in range(4):
            lsn = val & nib_mask
            val >>= 4
            vtx.append(lsn)

        return vtx

    @staticmethod
    def randint(length: int = 1, bit_mode: bool = False) -> int:
        if length < 1:
            raise ValueError("Length starts from 1.")

        if bit_mode:
            return randint(0, (1 << length) - 1)

        return randint(0, (1 << (length * 8)) - 1)

    @staticmethod
    def pad_random(data: int, data_byte_length: int, total_byte_length: int = 2) -> Tuple[int, int | None]:
        """
        Returns
            (padded_data, None) if data byte length is 1
            or
            (data, padding) if data byte length is 2
        """
        if data_byte_length < 0 and total_byte_length < 0:
            raise ValueError("Length starts from 0.")

        if data_byte_length > 0 and data_byte_length < total_byte_length:
            # data, none
            pad_nib_length = (total_byte_length - data_byte_length) * 2
            pad = Bit.randint(pad_nib_length * 4, True)

            pad >>= 4 # discard a nibble
            pad = Bit.prepend_nibble(pad_nib_length, pad) # add pad count

            # inplace padding
            data <<= pad_nib_length * 4
            data ^= pad

            return data, None

        # add the padding yourself!
        pad = Bit.randint(total_byte_length)
        pad >>= 4 # discard a nibble
        pad = Bit.prepend_nibble(total_byte_length * 2, pad) # add pad count

        return data, pad

    @staticmethod
    def remove_pad(data: int, byte_length: int = 1) -> int | None:
        """
        last nibble always tell how many nibble
        is a pad.
        return None if all of the data is padding.
        """
        lsn_mask = 0b1111
        pad_count = data & lsn_mask
        if pad_count == (byte_length * 2):
            return None # all of data is padding
        return data >> (pad_count * 4) # per nibble
