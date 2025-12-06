

class FeistelCipher:


    # Initialize the cipher with a secret key and number of rounds
    # Key: The string used to encrypt/decrypt
    # Rounds: Number of times the data is shuffled (Default: 16)
    def __init__(self, key: str, rounds: int = 16):

        # Convert the key string into a numeric seed (simple hash)
        self.key_val = sum([ord(c) for c in key])
        self.rounds = rounds

    # The 'F' function in the Feistel network; Mixes data based on the key and current round number
    # Mathematical logic: (Right + Key + RoundIndex) XOR Key
    def _round_function(self, right_val: int, round_idx: int) -> int:

        return (right_val + self.key_val + round_idx) ^ self.key_val

    # Function that processes (encrypts or decrypts) a single block (2 characters)
    # Mode: 'encrypt' or 'decrypt'
    def _process_block(self, left_char: str, right_char: str, mode: str) -> tuple:

        # Convert characters to integer Unicode values
        L = ord(left_char)
        R = ord(right_char)


        # Encryption: 0 -> 15
        # Decryption: 15 -> 0 (reverse)
        round_range = range(self.rounds) if mode == 'encrypt' else range(self.rounds - 1, -1, -1)

        for i in round_range:
            # Store the old Right side
            prev_R = R

            # Calculate new Right: Old Left XOR F(Old Right, Key)
            f_result = self._round_function(R, i)
            R = L ^ f_result

            # New Left becomes the Old Right
            L = prev_R

        # After the final round, we swap L and R to make the operation symmetrical and this is standard in DES and other Feistel ciphers
        L, R = R, L

        # Convert integers back to characters
        return chr(L), chr(R)

    # Function that encrypts a full text string
    def encrypt(self, text: str) -> str:

        # Padding: If length is odd, add a placeholder.
        if len(text) % 2 != 0:
            text += " "  # Padding with space

        encrypted_text = []

        # Process text in chunks of 2 characters
        for i in range(0, len(text), 2):
            l_char = text[i]
            r_char = text[i + 1]

            new_l, new_r = self._process_block(l_char, r_char, mode='encrypt')
            encrypted_text.append(new_l + new_r)

        return "".join(encrypted_text)

    # Function that decrypts the full encrypted string
    def decrypt(self, encrypted_text: str) -> str:

        decrypted_text = []

        for i in range(0, len(encrypted_text), 2):
            l_char = encrypted_text[i]
            r_char = encrypted_text[i + 1]

            new_l, new_r = self._process_block(l_char, r_char, mode='decrypt')
            decrypted_text.append(new_l + new_r)

        return "".join(decrypted_text)

