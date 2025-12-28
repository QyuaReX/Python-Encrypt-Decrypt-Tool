# 🛡️ Python CLI Encryption Tool (Feistel Cipher + SHA-256)

A command-line encryption and decryption tool built from scratch in Python.
Unlike standard tools that use pre-made libraries (like `AES`), this project implements a **custom Feistel Cipher network** for educational purposes, paired with **SHA-256 hashing** to ensure data integrity.

## 🚀 Features

* **Custom Encryption Engine:** Implements a text-based Feistel Cipher (similar structure to DES/Blowfish).
* **Integrity Verification:** Uses **SHA-256** checksums to detect if a file has been tampered with or if the wrong password was used.
* **Robust File Handling:**
    * Handles **Base64** encoding to safely store encrypted data.
    * Auto-detects **PowerShell (UTF-16)** and **UTF-8** encodings to prevent crashes.
    * Supports **Output Directories** (`-od`) with auto-creation.
* **Smart CLI & UX:**
    * **"Hacker" Loading Animation:** Visual feedback during processing (toggleable).
    * **Secure Input:** Hidden password input by default, with optional **Asterisk (`****`)** mode for Windows.
    * **Cross-Platform:** Works on Windows, Linux, and MacOS.

## 📦 Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/QyuaReX/Python-Encrypt-Decrypt-Tool.git
    cd Python-Encrypt-Decrypt-Tool
    ```
2.  No external libraries are required! The tool uses Python's standard library.
3.  Run the tool:
    ```bash
    python main.py -h
    ```

## 📖 Usage Guide

### 1. Basic Encryption
Encrypts `secret.txt` and saves it as `secret.txt.enc`.
```bash
python main.py --encrypt --file secret.txt
```
*(You will be prompted to enter the password securely).*

### 2. Basic Decryption
Decrypts `secret.txt.enc` back to `secret.txt`.
```bash
python main.py --decrypt --file secret.txt.enc
```

### 3. Advanced Options

**Save to a specific folder (Auto-creates folder if missing):**
```bash
python main.py -e -f secret.txt -od "Results/Vault"
```

**Use Asterisk (`****`) input (Windows Only):**
```bash
python main.py -e -f secret.txt --asterisk
```

**Fast Mode (Disable Animation):**
```bash
python main.py -d -f big_file.txt.enc --fast
```

**Combine Everything:**
```bash
python main.py -e -f data.txt -od Desktop -o final.dat --fast
```

## 🛠️ Command Reference

| Flag | Description |
| :--- | :--- |
| `-e`, `--encrypt` | Enable Encryption Mode. |
| `-d`, `--decrypt` | Enable Decryption Mode. |
| `-f`, `--file` | Input file path (Required). |
| `-o`, `--output` | Custom output filename (Optional). |
| `-od`, `--out-dir`| Custom output directory. Auto-creates if missing. |
| `-k`, `--key` | Provide password in command (Not recommended for security). |
| `--fast` | Disable the visual loading animation. |
| `--asterisk` | Show `****` while typing password (Windows Only). |

## 🧠 Technical Architecture

### The Algorithm: Feistel Network
The tool splits data blocks into **Left (L)** and **Right (R)** halves. It applies a round function `F` and mixes them using **XOR** operations over 16 rounds.

$$ L_{i+1} = R_i $$
$$ R_{i+1} = L_i \oplus F(R_i, K_i) $$

### Integrity Check (SHA-256)
To prevent "garbage output" when a wrong password is used, the tool appends a hash to the encrypted file:
`[ Encrypted Data ] + [ SHA-256 Hash ]`

During decryption, the tool:
1.  Decrypts the data.
2.  Calculates the hash of the result.
3.  Compares it with the stored hash.
4.  **If they don't match, it alerts the user and aborts the save.**


## 📂 Project Structure

```
.
├── core/
│   ├── feistel.py       # The encryption engine logic
│   └── file_handler.py  # Handles file I/O, Base64, and Encoding logic
├── main.py              # CLI entry point, Toggles, and Animation logic
├── requirements.txt     # Dependencies (Standard Lib only)
└── README.md            # Documentation
```

## ⚠️ Disclaimer
This tool is for **educational purposes**. While it implements robust logic (Feistel Structure, SHA-256), custom crypto implementations should not be used for high-security applications in production.