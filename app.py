from src.mini_aes.logs.LogManager import LogManager
from src.mini_aes import EncryptionFacade
from src.mini_aes import DecryptionFacade
from src.mini_aes.io.files.factories.FileReaderFactory import FileReaderFactory
from src.mini_aes.io.files.factories.FileWriterFactory import FileWriterFactory
from io import BytesIO
import streamlit as st
import datetime

if "log" not in st.session_state:
        st.session_state.log = ''

st.title("Mini AES")

mode = st.radio(
    "Choose encryption/decryption method.",
    [
        "Nonblock Encryption (2 bytes)",
        "Nonblock Decryption (2 bytes)",
        "Block Encryption (ECB)",
        "Block Decryption (ECB)",
        "Block Encryption (CBC)",
        "Block Decryption (CBC)",
    ]
)

uploaded_key_file = st.file_uploader("Upload key")
uploaded_file = st.file_uploader("Upload file")

start_process = st.button("Start Encryption/Decryption")

download_result = st.empty()

st.text_area("Log", value=st.session_state.log, height=500, key="log_viewer", disabled=True)
st.download_button(
    label="Download Log",
    data=st.session_state.log,
    file_name=f"log {datetime.datetime.today().strftime('%Y-%m-%d %H-%M-%S')}.txt"
)

def update_text_area(event: str):
    st.session_state.log += event + '\n'

if uploaded_key_file and uploaded_file:
    # data = uploaded_file.read()
    # key_data = uploaded_key_file.read()
    # key_buffer = BytesIO(key_data)
    # data_buffer = BytesIO(data)

    if start_process:
        key = FileReaderFactory.create(
            'binary',
            file_io=uploaded_key_file
        )
        uploaded = FileReaderFactory.create(
            'binary',
            file_io=uploaded_file
        )
        result_io = BytesIO()
        result = FileWriterFactory.create(
            'binary',
            file_io=result_io
        )
        log_manager = LogManager()

        log_manager.subscribe(update_text_area)

        try:
            if mode == "Nonblock Encryption (2 bytes)":
                EncryptionFacade.encrypt(
                    plaintext=uploaded,
                    key=key,
                    ciphertext=result,
                    block='nonblock',
                    logger=log_manager
                )
            elif mode == "Nonblock Decryption (2 bytes)":
                DecryptionFacade.decrypt(
                    ciphertext=uploaded,
                    key=key,
                    plaintext=result,
                    block='nonblock',
                    logger=log_manager
                )
            elif mode == "Block Encryption (ECB)":
                EncryptionFacade.encrypt(
                    plaintext=uploaded,
                    key=key,
                    ciphertext=result,
                    block='block',
                    block_mode='ecb',
                    logger=log_manager
                )
            elif mode == "Block Decryption (ECB)":
                DecryptionFacade.decrypt(
                    ciphertext=uploaded,
                    key=key,
                    plaintext=result,
                    block='block',
                    block_mode='ecb',
                    logger=log_manager
                )
            elif mode == "Block Encryption (CBC)":
                EncryptionFacade.encrypt(
                    plaintext=uploaded,
                    key=key,
                    ciphertext=result,
                    block='block',
                    block_mode='cbc',
                    logger=log_manager
                )
            elif mode == "Block Decryption (CBC)":
                DecryptionFacade.decrypt(
                    ciphertext=uploaded,
                    key=key,
                    plaintext=result,
                    block='block',
                    block_mode='cbc',
                    logger=log_manager
                )
            else:
                st.warning("Invalid mode.")

            result_io.seek(0)
            download_result.download_button(
                label="Download Result",
                data=result_io,
                file_name=f"result-mini-aes {datetime.datetime.today().strftime('%Y-%m-%d %H-%M-%S')}"
            )
        except Exception as e:
            st.error(e)
            raise e

