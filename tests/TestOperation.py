import unittest
from unittest import mock
from unittest.mock import Mock
from itertools import cycle
from mini_aes.operations.KeyOperation import KeyOperation
from mini_aes.operations.GeneralOperation import GeneralOperation
from mini_aes.operations.EncryptionOperationBase import EncryptionOperationBase
from mini_aes.operations.DecryptionOperationBase import DecryptionOperationBase
from mini_aes.block_mode.operations.BlockEncryptionOperation import BlockEncryptionOperation
from mini_aes.block_mode.operations.BlockDecryptionOperation import BlockDecryptionOperation
from mini_aes.nonblock_mode.operations.NonBlockEncryptionOperation import NonBlockEncryptionOperation
from mini_aes.nonblock_mode.operations.NonBlockDecryptionOperation import NonBlockDecryptionOperation

class TestOperation(unittest.TestCase):
    def test_key_rot_byte(self):
        # test a static method
        self.assertEqual(KeyOperation._rot_byte(0b11110000), 0b00001111)
        self.assertEqual(KeyOperation._rot_byte(0b00001111), 0b11110000)
        self.assertEqual(KeyOperation._rot_byte(0x1A), 0xA1)

    def test_key_get_round_constant_invalid_index(self):
        with self.assertRaises(ValueError) as context:
            KeyOperation._get_round_constant(0)
        self.assertIn("from 1", context.exception.args[0])

    def test_key_get_round_constant(self):
        # test a static method
        #! currently only care for 1st, 2nd, and 3rd round
        self.assertEqual(KeyOperation._get_round_constant(3), 0b100)
        self.assertEqual(KeyOperation._get_round_constant(2), 0b010)
        self.assertEqual(KeyOperation._get_round_constant(1), 0b001)

    def test_key_get_round_key(self):
        mock_KeyBase_0000 = Mock()
        mock_KeyBase_0000.read_data = Mock(return_value=(0x0000, 2))

        key_operation = KeyOperation(mock_KeyBase_0000)
        self.assertEqual(key_operation.get_round_key(1), 0xefef) # 0xe from s-box(0x0),
                                                                 # lsb xor 0xee with 0x1 (rcon1) become 0xef,
                                                                 # msb xor 0x00 with 0xef become 0xef,
                                                                 # prepend lsb and msb (little), 0xefef

    def test_sub_nibble_and_inv(self):
        for i in range(0x10):
            self.assertEqual(GeneralOperation._inv_sub_nibble(GeneralOperation._sub_nibble(i)), i)

    def test_sub_nibbles_and_inv(self):
        for i in range(0x100):
            self.assertEqual(GeneralOperation._inv_sub_nibbles(KeyOperation._sub_nibbles(i, 2), 2), i)

    def test_encryption_shift_rows(self):
        # test a static method
        self.assertEqual(EncryptionOperationBase._shift_rows(0xFFFF), 0xFFFF)
        self.assertEqual(EncryptionOperationBase._shift_rows(0xDCBA), 0xBCDA)
        self.assertEqual(EncryptionOperationBase._shift_rows(0xBCDA), 0xDCBA)

    def test_decryption_inv_sub_nibble(self):
        # test a static method
        self.assertEqual(GeneralOperation._inv_sub_nibble(0xE), 0x0)
        self.assertEqual(GeneralOperation._inv_sub_nibble(0x4), 0x1)
        self.assertEqual(GeneralOperation._inv_sub_nibble(0x7), 0xF)
        self.assertEqual(GeneralOperation._inv_sub_nibble(0x4), 0x1)

    def test_decryption_inv_shift_rows(self):
        # test a static method
        self.assertEqual(EncryptionOperationBase._shift_rows(0xFFFF), 0xFFFF)
        self.assertEqual(EncryptionOperationBase._shift_rows(0xDCBA), 0xBCDA)
        self.assertEqual(EncryptionOperationBase._shift_rows(0xBCDA), 0xDCBA)

    def test_mix_columns_and_inv(self):
        # test a static method
        for vtx in range(0x10000):
            mix = EncryptionOperationBase._mix_columns(vtx)
            re_mix = DecryptionOperationBase._inv_mix_columns(mix)
            self.assertEqual(vtx, re_mix)

    def test_encrypt_decrypt_do_rounds(self):
        def hamming_distance(a, b):
            return bin(a ^ b).count('1')

        mock_KeyBase_0000 = Mock()
        mock_KeyBase_0000.read_data = Mock(return_value=(0x0000, 2))
        key_operation_0000 = KeyOperation(mock_KeyBase_0000)

        # should be agnostic to block or nonblock
        enc_nonblock_ops = NonBlockEncryptionOperation(
            None,
            key_operation_0000,
            None,
        )
        enc_block_ops_ecb = BlockEncryptionOperation(
            None,
            key_operation_0000,
            None,
            'ecb'
        )
        enc_block_ops_cbc = BlockEncryptionOperation(
            None,
            key_operation_0000,
            None,
            'cbc'
        )

        dec_nonblock_ops = NonBlockDecryptionOperation(
            None,
            key_operation_0000,
            None,
        )
        dec_block_ops_ecb = BlockDecryptionOperation(
            None,
            key_operation_0000,
            None,
            'ecb'
        )
        dec_block_ops_cbc = BlockDecryptionOperation(
            None,
            key_operation_0000,
            None,
            'cbc'
        )

        distance = 0
        for i in range(0x10000):
            nonblock_ciphertext = enc_nonblock_ops._do_rounds(i)
            distance += hamming_distance(i, nonblock_ciphertext)
            self.assertEqual(
                dec_nonblock_ops._do_inv_rounds(nonblock_ciphertext),
                i
            )
            self.assertEqual(
                dec_block_ops_ecb._do_inv_rounds(enc_block_ops_ecb._do_rounds(i)),
                i
            )
            self.assertEqual(
                dec_block_ops_cbc._do_inv_rounds(enc_block_ops_cbc._do_rounds(i)),
                i
            )
        print(f'Average state change in nonblock decryption with key 0x000 and state from 0x0000 to 0xFFFF is {distance / 0xFFFF}')

    def test_nonblock_encrypt_decrypt(self):
        plain_orig = (0xABCD, 2)
        mock_KeyBase_ABCD = Mock()
        mock_KeyBase_ABCD.read_data = Mock(return_value=(0x1111, 2))
        key_operation_ABCD = KeyOperation(mock_KeyBase_ABCD)

        mock_PlaintextBase_read = Mock()
        mock_CiphertextBase_read = Mock()

        mock_CiphertextBase_write = Mock()
        mock_CiphertextBase_write.write_data = Mock(return_value=None)

        mock_PlaintextBase_write = Mock()
        mock_PlaintextBase_write.write_data = Mock(return_value=None)

        enc_nonblock_ops = NonBlockEncryptionOperation(
            mock_PlaintextBase_read,
            key_operation_ABCD,
            mock_CiphertextBase_write,
        )

        dec_nonblock_ops = NonBlockDecryptionOperation(
            mock_CiphertextBase_read,
            key_operation_ABCD,
            mock_PlaintextBase_write,
        )

        mock_PlaintextBase_read.read_data = Mock(return_value=plain_orig)
        enc_nonblock_ops.encrypt()
        cipher = (mock_CiphertextBase_write.write_data.call_args[0][0], 2)

        mock_CiphertextBase_read.read_data = Mock(return_value=cipher)
        dec_nonblock_ops.decrypt()
        plain = mock_PlaintextBase_write.write_data.call_args[0][0]

        self.assertEqual(plain_orig[0], plain)

    def test_block_encrypt_decrypt_full_pad(self):
        plain_orig = [
            [(0x0000, 2), (0xABCD, 2), (None, 0)],
            [(0x0001, 2), (0x1000, 2), (None, 0)],
        ]

        mock_KeyBase_ABCD = Mock()
        mock_KeyBase_ABCD.read_data = Mock(return_value=(0x1111, 2))
        key_operation_ABCD = KeyOperation(mock_KeyBase_ABCD)

        mock_PlaintextBase_read = Mock()
        mock_CiphertextBase_read = Mock()
        mock_PlaintextBase_read.ended = Mock()
        mock_CiphertextBase_read.ended = Mock()

        mock_CiphertextBase_write = Mock()
        mock_PlaintextBase_write = Mock()

        enc_block_ecb_ops = BlockEncryptionOperation(
            mock_PlaintextBase_read,
            key_operation_ABCD,
            mock_CiphertextBase_write,
            'ecb'
        )

        enc_block_cbc_ops = BlockEncryptionOperation(
            mock_PlaintextBase_read,
            key_operation_ABCD,
            mock_CiphertextBase_write,
            'cbc'
        )

        dec_block_ecb_ops = BlockDecryptionOperation(
            mock_CiphertextBase_read,
            key_operation_ABCD,
            mock_PlaintextBase_write,
            'ecb'
        )

        dec_block_cbc_ops = BlockDecryptionOperation(
            mock_CiphertextBase_read,
            key_operation_ABCD,
            mock_PlaintextBase_write,
            'cbc'
        )

        for i in plain_orig:
            #### Test ECB ####
            mock_PlaintextBase_read.ended.side_effect = cycle((False,True))
            mock_CiphertextBase_read.ended.side_effect = cycle((False,False,True))
            mock_CiphertextBase_write.write_data = Mock(return_value=None)
            mock_PlaintextBase_write.write_data = Mock(return_value=None)
            ciphers = []
            mock_PlaintextBase_read.read_data.side_effect = cycle(i)
            # mock_CiphertextBase_read.read_data.side_effect = cycle(i)
            enc_block_ecb_ops.encrypt()
            for call in mock_CiphertextBase_write.write_data.call_args_list:
                ciphers.append((call[0][0], 2))
            ciphers.append((None, 0))
            # print(ciphers)

            mock_CiphertextBase_read.read_data = Mock(side_effect=cycle(ciphers))
            dec_block_ecb_ops.decrypt()

            plain = []
            for call in mock_PlaintextBase_write.write_data.call_args_list:
                plain.append((call[0][0], 2))

            for j in range(len(plain)):
                self.assertEqual(i[j][0], plain[j][0])

            #### Test CBC ####
            # mock_PlaintextBase_read.ended.side_effect = cycle((False,True))
            # mock_CiphertextBase_read.ended.side_effect = cycle((False,False,True))
            mock_CiphertextBase_write.write_data = Mock(return_value=None)
            mock_PlaintextBase_write.write_data = Mock(return_value=None)
            ciphers = []
            mock_PlaintextBase_read.read_data.side_effect = cycle(i)
            enc_block_cbc_ops.encrypt()
            for call in mock_CiphertextBase_write.write_data.call_args_list:
                ciphers.append((call[0][0], 2))
            ciphers.append((None, 0))
            # print(ciphers)

            mock_CiphertextBase_read.read_data = Mock(side_effect=cycle(ciphers))
            dec_block_cbc_ops.decrypt()

            plain = []
            for call in mock_PlaintextBase_write.write_data.call_args_list:
                plain.append((call[0][0], 2))

            for j in range(len(plain)):
                self.assertEqual(i[j][0], plain[j][0])

    def test_block_encrypt_decrypt_inplace_pad(self):
        plain_orig = [
            [(0x0000, 2), (0xAB, 1), (None, 0)],
            [(0x0001, 2), (0x10, 1), (None, 0)],
        ]

        mock_KeyBase_ABCD = Mock()
        mock_KeyBase_ABCD.read_data = Mock(return_value=(0x1111, 2))
        key_operation_ABCD = KeyOperation(mock_KeyBase_ABCD)

        mock_PlaintextBase_read = Mock()
        mock_CiphertextBase_read = Mock()
        mock_PlaintextBase_read.ended = Mock()
        mock_CiphertextBase_read.ended = Mock()

        mock_CiphertextBase_write = Mock()
        mock_PlaintextBase_write = Mock()

        enc_block_ecb_ops = BlockEncryptionOperation(
            mock_PlaintextBase_read,
            key_operation_ABCD,
            mock_CiphertextBase_write,
            'ecb'
        )

        enc_block_cbc_ops = BlockEncryptionOperation(
            mock_PlaintextBase_read,
            key_operation_ABCD,
            mock_CiphertextBase_write,
            'cbc'
        )

        dec_block_ecb_ops = BlockDecryptionOperation(
            mock_CiphertextBase_read,
            key_operation_ABCD,
            mock_PlaintextBase_write,
            'ecb'
        )

        dec_block_cbc_ops = BlockDecryptionOperation(
            mock_CiphertextBase_read,
            key_operation_ABCD,
            mock_PlaintextBase_write,
            'cbc'
        )

        for i in plain_orig:
        # for i in [plain_orig[0]]:
            # print(i)

            #### Test ECB ####
            mock_PlaintextBase_read.ended.side_effect = cycle((False,True))
            mock_CiphertextBase_read.ended.side_effect = cycle((False,True))
            mock_CiphertextBase_write.write_data = Mock(return_value=None)
            mock_PlaintextBase_write.write_data = Mock(return_value=None)
            ciphers = []
            mock_PlaintextBase_read.read_data.side_effect = cycle(i)
            # mock_CiphertextBase_read.read_data.side_effect = cycle(i)
            enc_block_ecb_ops.encrypt()
            for call in mock_CiphertextBase_write.write_data.call_args_list:
                ciphers.append((call[0][0], 2))
            ciphers.append((None, 0))
            # print(ciphers)

            mock_CiphertextBase_read.read_data = Mock(side_effect=cycle(ciphers))
            dec_block_ecb_ops.decrypt()

            plain = []
            for call in mock_PlaintextBase_write.write_data.call_args_list:
                plain.append((call[0][0], 2))
            # print(plain)

            for j in range(len(plain)):
                self.assertEqual(i[j][0], plain[j][0])

            # #### Test CBC ####
            mock_PlaintextBase_read.ended.side_effect = cycle((False,True))
            mock_CiphertextBase_read.ended.side_effect = cycle((False,True))
            mock_CiphertextBase_write.write_data = Mock(return_value=None)
            mock_PlaintextBase_write.write_data = Mock(return_value=None)
            ciphers = []
            mock_PlaintextBase_read.read_data.side_effect = cycle(i)
            # mock_CiphertextBase_read.read_data.side_effect = cycle(i)
            enc_block_cbc_ops.encrypt()
            for call in mock_CiphertextBase_write.write_data.call_args_list:
                ciphers.append((call[0][0], 2))
            ciphers.append((None, 0))
            # print(ciphers)

            mock_CiphertextBase_read.read_data = Mock(side_effect=cycle(ciphers))
            dec_block_cbc_ops.decrypt()

            plain = []
            for call in mock_PlaintextBase_write.write_data.call_args_list:
                plain.append((call[0][0], 2))
            # print(plain)

            for j in range(len(plain)):
                self.assertEqual(i[j][0], plain[j][0])

    def test_block_encrypt_decrypt_inplace_pad_file(self):
        """
        Up to you if you want to run this test, but remember to clean
        the used file.
        i don't want to automate cleaning it! (for now)
        """
        from os import remove
        from mini_aes.block_mode.data.BlockKey import BlockKey
        from mini_aes.block_mode.data.BlockPlaintext import BlockPlaintext
        from mini_aes.block_mode.data.BlockCiphertext import BlockCiphertext
        from mini_aes.nonblock_mode.data.NonBlockKey import NonBlockKey
        from mini_aes.nonblock_mode.data.NonBlockPlaintext import NonBlockPlaintext
        from mini_aes.nonblock_mode.data.NonBlockCiphertext import NonBlockCiphertext
        from mini_aes.io.files.implementations.BinaryFileReader import BinaryFileReader
        from mini_aes.io.files.implementations.BinaryFileWriter import BinaryFileWriter

        try:
            a = BinaryFileWriter("./key_aa")
            a.write("aa", True)

            a = BinaryFileWriter("./plaintext_aa")
            a.write("aa", True)

            a = BinaryFileWriter("./plaintext_aaaa")
            a.write("aaaa", True)

            a = BinaryFileWriter("./plaintext_aaa")
            a.write("aaa", True)

            key_a = KeyOperation(
                NonBlockKey(
                    BinaryFileReader("./key_aa")
                )
            )

            nonblock_plaintext = NonBlockPlaintext(
                BinaryFileReader("./plaintext_aa"), 'enc'
            )
            nonblock_ciphertext = NonBlockCiphertext(
                BinaryFileWriter("./ciphertext_nonblock_aa"), 'enc'
            )
            enc_nonblock = NonBlockEncryptionOperation(
                nonblock_plaintext,
                key_a,
                nonblock_ciphertext
            )
            enc_nonblock.encrypt()

            nonblock_plaintext = NonBlockPlaintext(
                BinaryFileWriter("./plaintext_test_nonblock_aa"), 'dec'
            )
            nonblock_ciphertext = NonBlockCiphertext(
                BinaryFileReader("./ciphertext_nonblock_aa"), 'dec'
            )
            dec_nonblock = NonBlockDecryptionOperation(
                nonblock_ciphertext,
                key_a,
                nonblock_plaintext,
            )
            dec_nonblock.decrypt()

            key_a = KeyOperation(
                BlockKey(
                    BinaryFileReader("./key_aa")
                )
            )

            block_plaintext = BlockPlaintext(
                BinaryFileReader("./plaintext_aaaa"), 'enc'
            )
            block_ciphertext = BlockCiphertext(
                BinaryFileWriter("./ciphertext_block_ecb_aaaa"), 'enc'
            )
            block_enc_ecb = BlockEncryptionOperation(
                block_plaintext,
                key_a,
                block_ciphertext,
                'ecb'
            )
            block_enc_ecb.encrypt()
            
            block_plaintext = BlockPlaintext(
                BinaryFileWriter("./plaintext_aaaa"), 'dec'
            )
            block_ciphertext = BlockCiphertext(
                BinaryFileReader("./ciphertext_block_ecb_aaaa"), 'dec'
            )
            block_enc_ecb = BlockDecryptionOperation(
                block_ciphertext,
                key_a,
                block_plaintext,
                'ecb'
            )
            block_enc_ecb.decrypt()

            block_plaintext = BlockPlaintext(
                BinaryFileReader("./plaintext_aaaa"), 'enc'
            )
            block_ciphertext = BlockCiphertext(
                BinaryFileWriter("./ciphertext_block_cbc_aaaa"), 'enc'
            )
            block_enc_cbc = BlockEncryptionOperation(
                block_plaintext,
                key_a,
                block_ciphertext,
                'cbc'
            )
            block_enc_cbc.encrypt()
            
            block_plaintext = BlockPlaintext(
                BinaryFileWriter("./plaintext_aaaa"), 'dec'
            )
            block_ciphertext = BlockCiphertext(
                BinaryFileReader("./ciphertext_block_cbc_aaaa"), 'dec'
            )
            block_enc_cbc = BlockDecryptionOperation(
                block_ciphertext,
                key_a,
                block_plaintext,
                'cbc'
            )
            block_enc_cbc.decrypt()
        except Exception as e:
            self.fail(f'Exception here: {e}')

if __name__ == '__main__':
    unittest.main()
