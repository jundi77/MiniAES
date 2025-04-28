import unittest
from mini_aes.utils.Bit import Bit

class TestBit(unittest.TestCase):
    def test_check_bit_negative(self):
        with self.assertRaises(ValueError) as context:
            Bit.check_bit(-1)
        self.assertIn("negative", context.exception.args[0])

    def test_check_bit_overflow(self):
        with self.assertRaises(OverflowError) as context:
            Bit.check_bit(2)
        self.assertIn("too big", context.exception.args[0])

    def test_check_2bytes_negative(self):
        with self.assertRaises(ValueError) as context:
            Bit.check_2bytes(-1)
        self.assertIn("negative", context.exception.args[0])

    def test_check_2bytes_overflow(self):
        with self.assertRaises(OverflowError) as context:
            Bit.check_2bytes(0xFFFF1)
        self.assertIn("too big", context.exception.args[0])

    def test_check_byte_negative(self):
        with self.assertRaises(ValueError) as context:
            Bit.check_byte(-1)
        self.assertIn("negative", context.exception.args[0])

    def test_check_byte_overflow(self):
        with self.assertRaises(OverflowError) as context:
            Bit.check_byte(0xFF1)
        self.assertIn("too big", context.exception.args[0])

    def test_check_nibble_negative(self):
        with self.assertRaises(ValueError) as context:
            Bit.check_nibble(-1)
        self.assertIn("negative", context.exception.args[0])

    def test_check_nibble_overflow(self):
        with self.assertRaises(OverflowError) as context:
            Bit.check_nibble(0b10000)
        self.assertIn("too big", context.exception.args[0])

    def test_split_2byte(self):
        lsb, msb = Bit.split_2byte(0xFF11)
        self.assertEqual(lsb, 0x11)
        self.assertEqual(msb, 0xFF)

    def test_split_byte(self):
        lsn, msn = Bit.split_byte(0xF1)
        self.assertEqual(lsn, 0x1)
        self.assertEqual(msn, 0xF)

    def test_prepend_bit(self):
        self.assertEqual(Bit.prepend_bit(0, 0), 0)
        self.assertEqual(Bit.prepend_bit(1, 0), 0b1)
        self.assertEqual(Bit.prepend_bit(0, 0b1), 0b10)
        self.assertEqual(Bit.prepend_bit(1, 0b1), 0b11)
        self.assertEqual(Bit.prepend_bit(1, 0b101), 0b1011)
        self.assertEqual(Bit.prepend_bit(0, 0b101), 0b1010)

    def test_prepend_nibble(self):
        self.assertEqual(Bit.prepend_nibble(0b0001, 0), 0b1)
        self.assertEqual(Bit.prepend_nibble(0b0101, 0), 0b101)
        self.assertEqual(Bit.prepend_nibble(0b1000, 0), 0b1000)
        self.assertEqual(Bit.prepend_nibble(0b1000, 0b1), 0b11000)
        self.assertEqual(Bit.prepend_nibble(0b1001, 0b111), 0b1111001)
        self.assertEqual(Bit.prepend_nibble(0b1001, 0b1111), 0b11111001)

    def test_prepend_byte(self):
        self.assertEqual(Bit.prepend_byte(0x01, 0), 0x1)
        self.assertEqual(Bit.prepend_byte(0x11, 0), 0x11)
        self.assertEqual(Bit.prepend_byte(0x11, 0xFF), 0xFF11)
        self.assertEqual(Bit.prepend_byte(0x11, 0xFFF), 0xFFF11)

    def test_get_nth_bit(self):
        self.assertEqual(Bit.get_nth_bit(0, 0b0), 0)
        self.assertEqual(Bit.get_nth_bit(0, 0b1), 1)
        self.assertEqual(Bit.get_nth_bit(0, 0b1001), 1)
        self.assertEqual(Bit.get_nth_bit(2, 0b1001), 0)
        self.assertEqual(Bit.get_nth_bit(6, 0b1001001), 1)

    def test_set_nth_bit(self):
        self.assertEqual(Bit.set_nth_bit(0, 1, 0b0), 1)
        self.assertEqual(Bit.set_nth_bit(0, 0, 0b1), 0)
        self.assertEqual(Bit.set_nth_bit(0, 1, 0b1001), 0b1001)
        self.assertEqual(Bit.set_nth_bit(2, 1, 0b1001), 0b1101)
        self.assertEqual(Bit.set_nth_bit(6, 0, 0b1001001), 0b0001001)

    def test_list_to_2bytes(self):
        self.assertEqual(Bit.list_to_2bytes([1, 2, 3, 4]), 0x4321)
        self.assertEqual(Bit.list_to_2bytes([1, 2, 3, 0]), 0x0321)

    def test_list_from_2bytes(self):
        self.assertEqual(Bit.list_from_2bytes(0x4321), [1, 2, 3, 4])

    def test_randint_length(self):
        with self.assertRaises(ValueError) as context:
            Bit.randint(0)
        self.assertIn("from 1", context.exception.args[0])

    def test_randint_byte_mode(self):
        self.assertLessEqual(Bit.randint(1), 0xFF)
        self.assertLessEqual(Bit.randint(2), 0xFFFF)
        self.assertLessEqual(Bit.randint(3), 0xFFFFFF)

    def test_randint_bit_mode(self):
        self.assertLessEqual(Bit.randint(1, True), 0b1)
        self.assertLessEqual(Bit.randint(2, True), 0b11)
        self.assertLessEqual(Bit.randint(3, True), 0b111)
        self.assertLessEqual(Bit.randint(4, True), 0b1111)

    def test_pad_random_inplace(self):
        data, pad = Bit.pad_random(0xF, 1, 2)
        self.assertEqual(pad, None)
        self.assertEqual(data & 0b1111, 2)

        data, pad = Bit.pad_random(0x0, 1, 2)
        self.assertEqual(pad, None)
        self.assertEqual(data & 0b1111, 2)

    def test_pad_random_add_it_yourself(self):
        data, pad = Bit.pad_random(0xFFFF, 2, 2)
        self.assertEqual(pad & 0b1111, 4)
        self.assertEqual(data, 0xFFFF)

        data, pad = Bit.pad_random(0xFF, 2, 2)
        self.assertEqual(pad & 0b1111, 4)
        self.assertEqual(data, 0xFF)

    def test_remove_pad_inplace(self):
        self.assertEqual(Bit.remove_pad(0xFFF1, 2), 0xFFF)
        self.assertEqual(Bit.remove_pad(0xFFF2, 2), 0xFF)
        self.assertEqual(Bit.remove_pad(0xFFF3, 2), 0xF)

        self.assertEqual(Bit.remove_pad(0xABC1, 2), 0xABC)
        self.assertEqual(Bit.remove_pad(0xABC2, 2), 0xAB)
        self.assertEqual(Bit.remove_pad(0xABC3, 2), 0xA)

    def test_remove_pad_all_padding(self):
        self.assertEqual(Bit.remove_pad(0xFFF4, 2), None)
        self.assertEqual(Bit.remove_pad(0xABC4, 2), None)

if __name__ == '__main__':
    unittest.main()
