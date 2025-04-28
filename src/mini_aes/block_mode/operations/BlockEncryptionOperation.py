from typing import Literal
from .BlockOperation import BlockOperation
from ..data.BlockPlaintext import BlockPlaintext
from ..data.BlockCiphertext import BlockCiphertext
from ...utils.Bit import Bit
from ...operations.KeyOperation import KeyOperation
from ...operations.EncryptionOperationBase import EncryptionOperationBase

class BlockEncryptionOperation(EncryptionOperationBase, BlockOperation):
    def __init__(self, plaintext: BlockPlaintext, key: KeyOperation, ciphertext: BlockCiphertext, mode: Literal["ecb", "cbc"]):
        BlockOperation.__init__(self, mode)
        EncryptionOperationBase.__init__(self, plaintext, key, ciphertext)

    def _encrypt_ecb(self) -> None:
        # # TODO bug hunt, directly decrypt to check
        # from ...block_mode.operations.BlockDecryptionOperation import BlockDecryptionOperation
        # decryptor = BlockDecryptionOperation(None, self._key, None, 'ecb')

        pad = None
        data, length = self._plaintext.read_data()
        if data is None:
            raise ValueError("Plaintext is empty.")

        if self._plaintext.ended():
            data, pad = Bit.pad_random(data, length, 2)

        while (data is not None):
            # self.log(f"Encryption will start for piece: {hex(data)}")
            # TODO bug hunt
            # TODO looks okay
            try:
                text = data.to_bytes((data.bit_length() + 7) // 8, 'little').decode()
                self.log(f"Encryption will start for piece: {text}")
            except:
                self.log(f"Encryption will start for piece: {hex(data)}")

            c = self._do_rounds(data)

            # # TODO bug hunt
            # text = decryptor._do_inv_rounds(c)
            # try:
            #     text = text.to_bytes((text.bit_length() + 7) // 8, 'little').decode()
            #     self.log(f"self check decrypt: {text}")
            # except:
            #     self.log(f"self check decrypt: {hex(text)}")
            # print(("first at loop, data", hex(data)))

            self._ciphertext.write_data(c)
            self.log(f"Encrypted to: {hex(c)}")
            # print(("first at loop, data", hex(data)))

            if pad is not None:
                self.log(f"Full pad: {hex(pad)}")
                self._ciphertext.write_data(self._do_rounds(pad))
                break

            # print(("ciphertext", hex(c)))
            data, length = self._plaintext.read_data()

            if data is not None and self._plaintext.ended():
                # print(("data check pad", (hex(data))))
                data, pad = Bit.pad_random(data, length, 2)
                # print(("data, pad", (hex(data), None if pad is None else hex(pad))))

        self._plaintext.close()
        self._ciphertext.close()

    def _encrypt_cbc(self) -> None:
        pad = None
        iv = Bit.randint(2)
        data, length = self._plaintext.read_data()
        if data is None:
            raise ValueError("Plaintext is empty.")

        if self._plaintext.ended():
            data, pad = Bit.pad_random(data, length, 2)

        self.log(f"Encryption will start for piece: {hex(data)}")
        self.log(f"IV is: {hex(iv)}")
        data ^= iv
        self.log(f"piece xored with iv: {hex(data)}")
        self._ciphertext.write_data(iv)
        # print(("iv gross", hex(iv)))

        while (data is not None):
            self.log(f"Encryption will start for piece: {hex(data)}")
            # print(("first at loop, data", hex(data)))
            c = self._do_rounds(data)
            self._ciphertext.write_data(c)
            self.log(f"piece encrypted to: {hex(c)}")
            # print(("block cipher", hex(c)))

            if pad is not None:
                self.log(f"Full pad: {hex(pad)}")
                pad ^= c
                self.log(f"Full pad xored with prev block: {hex(pad)}")
                self._ciphertext.write_data(self._do_rounds(pad))
                break

            data, length = self._plaintext.read_data()
            if data is not None:
                if self._plaintext.ended():
                    # print(("ended at", hex(data)))
                    data, pad = Bit.pad_random(data, length, 2)
                self.log(f"continue for piece: {hex(data)}")
                data ^= c
                self.log(f"piece xored with prev block: {hex(data)}")

        self._plaintext.close()
        self._ciphertext.close()

    def encrypt(self) -> None:
        if self._mode == "ecb":
            self._encrypt_ecb()
        elif self._mode == "cbc":
            self._encrypt_cbc()
