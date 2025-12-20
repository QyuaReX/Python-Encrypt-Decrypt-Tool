import argparse
import sys
import getpass
import hashlib
from core.feistel import FeistelCipher
from core.file_handler import FileHandler
import time
import os

# Try to import Windows-specific library for asterisks
# If the user is on Linux/Mac, this import fails
try:
    import msvcrt

    WINDOWS_MODE = True
except ImportError:
    WINDOWS_MODE = False

# Constant
HASH_LENGTH = 64  # SHA-256 produces a 64-character hex string


# Function generates asterisks (*) while typing in the secure key, only works on Windows
def get_password_with_asterisks(prompt='Password: '):
    # Safety check: If not on Windows, fallback to standard invisible input
    if not WINDOWS_MODE:
        print("[!] Asterisk input is only supported on Windows. Using standard secure input.")
        return getpass.getpass(prompt)

    sys.stdout.write(prompt)
    sys.stdout.flush()
    password = []

    while True:
        ch = msvcrt.getch()  # <---Get a single character

        # Enter key pressed
        if ch == b'\r' or ch == b'\n':
            print('')
            break

        # Backspace key pressed
        elif ch == b'\x08':
            if len(password) > 0:
                password.pop()
                # Move cursor back, overwrite with space, move back again
                sys.stdout.write('\b \b')
                sys.stdout.flush()

        # Ctrl+C (Interrupt)
        elif ch == b'\x03':
            raise KeyboardInterrupt

        # Normal character
        else:
            try:
                char = ch.decode('utf-8')
                password.append(char)
                sys.stdout.write('*')  # Print the asterisk
                sys.stdout.flush()
            except:
                pass

    return ''.join(password)


# Function that simulates a loading bar ("hacker effect")
def visual_loading(message: str, duration: int = 2):
    print(f"[*] {message}...")

    toolbar_width = 40

    # Set up the loading loop
    for i in range(toolbar_width + 1):
        time.sleep(duration / toolbar_width)

        # Logic to create the bar: [#####     ]
        bar = '█' * i + '-' * (toolbar_width - i)

        sys.stdout.write(f"\r[{bar}] {int(i / toolbar_width * 100)}%")
        sys.stdout.flush()

    print("\n")  # <---New line


# Function that calculates where to save the file based on arguments (--out-dir; -od)
def resolve_output_path(args, mode: str) -> str:
    # Default; Saves where the input files was (either encrypted or decrypted file)
    default_path = FileHandler.generate_output_path(args.file, mode)

    # If the user specified a custom folder (-od)
    if args.out_dir:
        # Create the folder if it doesn't exist
        if not os.path.exists(args.out_dir):
            try:
                os.makedirs(args.out_dir)
                print(f"[*] Created new directory: {args.out_dir}")
            except OSError as e:
                print(f"[!] Error creating directory: {e}")
                sys.exit(1)

        # Extract just the filename (removes the old path)
        filename = os.path.basename(default_path)

        # If the user created a custom output name (-o), use that filename instead
        if args.output:
            filename = args.output

        # Combines custom folder and filename
        return os.path.join(args.out_dir, filename)  # The front/backslash solution; It works on Mac/Linux and Windows no matter the slash

    # If no custom folder, check for a custom filename (-o)
    if args.output:
        return args.output

    # Use the default path
    return default_path


# Function generates a SHA-256; Used for verification of the decrypted text (if the password is valid)
# Extraa safety!!!
def get_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# Function that handles the encryption
def run_encryption(args):
    print(f"[*] Reading file: {args.file}")
    try:
        plaintext = FileHandler.read_file(args.file)
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return

    # Generate Hash of the original text
    checksum = get_hash(plaintext)

    # Encrypt the content
    cipher = FeistelCipher(args.key)
    encrypted_content = cipher.encrypt(plaintext)

    # Append the hash to the encrypted content
    # Structure: [EncryptedString][64-char-Hash]
    # The encrypted file (text) along with the password gets saved together, with the password/key always being the last 64 characters
    final_payload = encrypted_content + checksum

    # Write to file
    output_path = resolve_output_path(args, 'encrypt')

    try:
        FileHandler.write_encrypted_file(output_path, final_payload)

        # Toggle check
        if not args.fast:  # Only show loading if --fast is NOT used
            visual_loading("Encrypting Data and Generating Hash")  # <---Magiccc


        print(f"[+] Success! Encrypted file saved to: {output_path}")
    except Exception as e:
        print(f"[!] Error saving file: {e}")


# Function that handles the decryption
def run_decryption(args):
    print(f"[*] Reading encrypted file: {args.file}")
    try:
        # This reads the Base64 file and gives us back the raw Cipher+Hash string
        raw_content = FileHandler.read_encrypted_file(args.file)
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return

    # Validation: Content must be longer than the hash itself
    # HASH_LENGTH is 64 characters (constant), if it is shorter that means that there was package loss/corruption
    if len(raw_content) < HASH_LENGTH:
        print("[!] Error: File content is too short. It might be corrupted.")
        return

    # Separate the Encrypted Data from the Hash
    stored_hash = raw_content[-HASH_LENGTH:]  # <---From the back and take the last 64 chars
    encrypted_data = raw_content[:-HASH_LENGTH]  # <---From the beginning and take everything except the last 64 chars

    # Toggle check
    if not args.fast:
        visual_loading("Decrypting and Verifying Integrity")  # <---Hollywood magic


    # Decrypt the data
    cipher = FeistelCipher(args.key)
    decrypted_text = cipher.decrypt(encrypted_data)

    # Verify Integrity
    calculated_hash = get_hash(decrypted_text)
    integrity_ok = False

    # Check 1: Perfect match?
    if calculated_hash == stored_hash:  # <---If the SHA-256 (64 bit strings of hash) are the same, the key is the same
        integrity_ok = True

    # Check 2: Try removing ONLY the last character (the padding; line 54 feistel.py)
    # Slicing [:-1] deletes one char (padding); .strip() was removed because it deletes all white space (PowerShell)
    elif decrypted_text.endswith(" "):
        candidate_text = decrypted_text[:-1]
        if get_hash(candidate_text) == stored_hash:
            decrypted_text = candidate_text
            integrity_ok = True

    if not integrity_ok:
        print("\n[!] CRITICAL WARNING: Integrity Check Failed!")
        print("[!] This means the PASSWORD IS WRONG or the file is corrupted.")
        print("[!] Decrypted data was NOT saved to prevent overwriting a correct file.")
        return

    print("[+] Integrity Verified: Password is correct.")

    # Save the result
    output_path = resolve_output_path(args, 'decrypt')

    try:
        FileHandler.write_file(output_path, decrypted_text)
        print(f"[+] Success! Decrypted file saved to: {output_path}")
    except Exception as e:
        print(f"[!] Error saving file: {e}")


# THE MAIN
def main():
    # Setup Argument Parser
    # CLI help menu, listens to flags
    parser = argparse.ArgumentParser(description="Python CLI Encryption Tool (Feistel Cipher)")  # <---Explain

    # Flags
    # Create groups so you can't choose both encrypt and decrypt at the same time
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-e', '--encrypt', action='store_true', help="Encrypt mode")
    group.add_argument('-d', '--decrypt', action='store_true', help="Decrypt mode")

    parser.add_argument('-f', '--file', required=True, help="Path to the input file")
    parser.add_argument('-o', '--output', help="Path to the output file (optional)")

    parser.add_argument('-od', '--out-dir', help="Directory to save the output file")

    parser.add_argument('-k', '--key', help="Encryption key (visible)")

    # TOGGLES for the "HOLLYWOOD EFFECTS"
    parser.add_argument('--fast', action='store_true', help="Disable the 'hacker' loading animation")
    parser.add_argument('--asterisk', action='store_true', help="Show asterisks (*) when typing password (Windows only)")


    args = parser.parse_args()

    # Secure Password Input
    # If key was not provided in arguments, ask for it securely
    if not args.key:

        # Check if user requested asterisks AND if they are on Windows
        if args.asterisk and WINDOWS_MODE:
            try:
                args.key = get_password_with_asterisks("Enter Encryption Key: ")
            except KeyboardInterrupt:
                print("\n[!] Operation cancelled.")
                sys.exit(1)
        else:
            # Default secure input (invisible)
            if args.asterisk and not WINDOWS_MODE:
                # Warning for Linux/Mac users
                print("[!] Asterisks are not supported on this OS. Using invisible input.")

            args.key = getpass.getpass("Enter Encryption Key: ")

    if not args.key:
        print("[!] Error: Key cannot be empty.")
        sys.exit(1)

    # Route to the correct function
    if args.encrypt:
        run_encryption(args)
    elif args.decrypt:
        run_decryption(args)


if __name__ == "__main__":
    main()