
import os
import base64 # Safer for storage


class FileHandler:

    # Function reads a file from the disk and returns the file as a string
    @staticmethod
    def read_file(filepath: str) -> str:

        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Error: The file '{filepath}' does not exist.")

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            # Just in case of binary/weird files
            raise ValueError("Error: The file is not a valid text file.")

    # Function writes content to a file as a string
    @staticmethod
    def write_file(filepath: str, content: str):

        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        except IOError as e:
            raise IOError(f"Error: Could not write to file '{filepath}'. Reason: {e}")

    # Function reads an encrypted file and decodes it from Base64 back to the internal encryption format
    @staticmethod
    def read_encrypted_file(filepath: str) -> str:

        content = FileHandler.read_file(filepath)
        try:
            # Decode Base64 string back to the "cipher string"
            decoded_bytes = base64.b64decode(content.encode('utf-8'))
            return decoded_bytes.decode('utf-8')  # <---Assuming internal cipher is utf-8 compatible

        except Exception:
            raise ValueError("Error: The file is corrupted or not a valid encrypted file.")

    # Function takes the encrypted string and converts it to Base64 and writes it to disk
    @staticmethod
    def write_encrypted_file(filepath: str, content: str):

        # Convert the cipher string to bytes, then to Base64 bytes, then back to UTF-8 string
        encoded_bytes = base64.b64encode(content.encode('utf-8'))
        safe_string = encoded_bytes.decode('utf-8')

        FileHandler.write_file(filepath, safe_string)

    # Function generates an output filename
    # If encrypting 'data.txt' -> 'data.txt.enc'
    # If decrypting 'data.txt.enc' -> 'data.txt.dec' (or removes .enc)
    @staticmethod
    def generate_output_path(filepath: str, mode: str) -> str:

        if mode == 'encrypt':
            return filepath + ".enc"
        elif mode == 'decrypt':
            if filepath.endswith(".enc"):
                return filepath[:-4]  # <---- removes .enc
            else:
                return filepath + ".dec"
        return filepath + ".out"

