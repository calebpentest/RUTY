---
# RUTY: A professional password security suite

![Screenshot 2025-04-06 162244](https://github.com/user-attachments/assets/1aa0ee29-d689-4ccd-aaf7-d2752769f2fd)


---

## Overview

**RUTY** is a command-line interface (CLI) password security suite designed for professionals and enthusiasts. It offers features such as password generation, hashing, breach checking, dictionary attacks, and encrypted vault storage, with a focus on security and usability.

- **Creator**: C4l3bpy
- **Version**: 3.0
- **Security Level**: Great

---

## Features

- 🔒 **Secure Password Generation**: Creates strong, random passwords (minimum 25 characters) with strength scoring via `zxcvbn`.
- 🔑 **Password Hashing**: Uses PBKDF2 with SHA-512 for secure hashing with customizable iterations.
- 🌐 **Breach Checking**: Queries the Have I Been Pwned API to check password exposure.
- ⚔️ **Dictionary Attacks**: Tests hashes against wordlists (e.g., `rockyou.txt`) with MD5, SHA-256, or SHA-512.
- 🏦 **Encrypted Vault**: Stores passwords securely with AES-256-CBC encryption using a master key.
- 💾 **Vault Backup**: Creates timestamped backups of your encrypted vault.
- 📜 **Logging**: Tracks operations in a secure log file.

---

## Installation

### Prerequisites

- Python 3.8

### Step 1: Download the Tool

Open your terminal and run:

```bash
git clone https://github.com/calebpentest/RUTY.git
cd RUTY
```

### Step 2: Install Requirements

Ensure you have Python and pip installed, then run:

```bash
pip install -r requirements.txt
```

This installs the necessary Python libraries:

- `cryptography`
- `colorama`
- `requests`
- `art`
- `zxcvbn`
- `shutil`

### Optional: Get `rockyou.txt` for Cracking Passwords

If you want to perform dictionary attacks:

- Download the `rockyou.txt` wordlist.
- Place it in the RUTY folder, or specify its path when prompted by the script.

---

## Running the Script

To get the tool working, use:

```bash
python ruty.py
```

### Menu Options

- **Generate a secure password**: Creates a strong password and displays its strength.
- **Hash password**: Hashes your password securely (with optional salt and iteration settings).
- **Check password breach**: Checks if your password has ever been leaked online.
- **Perform dictionary attack**: Attempts to crack a password hash using a wordlist (like `rockyou.txt`).
- **Save password to vault**: Encrypts and stores a password securely.
- **Retrieve from vault**: Decrypts and displays a saved password.
- **Backup vault**: Creates a backup of your secure password vault.
- **Exit**: Closes the tool safely.

---

## 💡Contributing

Would you like to help improve RUTY? You are welcome to contribute.
Here's how:

1. Fork the GitHub repository.
2. Create a new branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```

3. Make your changes and commit:

   ```bash
   git commit -m "Add new feature"
   ```

4. Push to your fork:

   ```bash
   git push origin feature/your-feature-name
   ```

5. Open a pull request on GitHub

---

Made with ❤️ by [C4l3bpy](https://github.com/calebpentest)

---
