import secrets
import string
import os
import hashlib
import requests
import base64
import json
import logging
from typing import Tuple, Optional, Dict
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from colorama import Fore, Style, init
from datetime import datetime
import art
import zxcvbn
import getpass
import shutil

HIBP_API = "https://api.pwnedpasswords.com/range/"
ROCKYOU_PATH = "rockyou.txt"
CONFIG_DIR = os.path.expanduser("~/.rutysec")
KEY_FILE = os.path.join(CONFIG_DIR, "master.key")
SALT_FILE = os.path.join(CONFIG_DIR, "salt.key")
VAULT_FILE = os.path.join(CONFIG_DIR, "vault.enc")
LOG_FILE = os.path.join(CONFIG_DIR, "rutysec.log")
DEFAULT_ITERATIONS = 2000000
MIN_PASSWORD_LENGTH = 25
VERSION = "3.0"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_config_directory():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
        os.chmod(CONFIG_DIR, 0o700)
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, 'a').close()
        os.chmod(LOG_FILE, 0o600)

def generate_master_key(key_file=KEY_FILE):
    setup_config_directory()
    if not os.path.exists(key_file):
        salt = secrets.token_bytes(32)
        kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1)
        master_pass = getpass.getpass("Enter master password: ")
        key = kdf.derive(master_pass.encode())
        with open(key_file, "wb") as f:
            f.write(key + salt)
        os.chmod(key_file, 0o400)
        logging.info("Master key generated")
    return load_master_key()

def load_master_key(key_file=KEY_FILE):
    if not os.path.exists(key_file):
        return generate_master_key()
    with open(key_file, "rb") as f:
        data = f.read()
        return data[:32]

def get_key_salt(key_file=KEY_FILE):
    with open(key_file, "rb") as f:
        data = f.read()
        return data[32:]

def generate_salt(salt_file=SALT_FILE):
    setup_config_directory()
    if not os.path.exists(salt_file):
        salt = secrets.token_bytes(32)
        with open(salt_file, "wb") as f:
            f.write(salt)
        os.chmod(salt_file, 0o400)
    with open(salt_file, "rb") as f:
        return f.read()

def encrypt_data(data, key):
    iv = secrets.token_bytes(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted

def decrypt_data(data, key):
    iv, encrypted = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data).decode() + unpadder.finalize()

def generate_password(length=MIN_PASSWORD_LENGTH):
    length = max(length, MIN_PASSWORD_LENGTH)
    char_pool = string.ascii_letters + string.digits + string.punctuation
    while True:
        pwd = ''.join(secrets.choice(char_pool) for _ in range(length))
        if (any(c.isupper() for c in pwd) and any(c.islower() for c in pwd) and 
            any(c.isdigit() for c in pwd) and any(c in string.punctuation for c in pwd)):
            return pwd

def secure_hash_password(password, salt=None, iterations=DEFAULT_ITERATIONS):
    salt = salt or generate_salt()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA512(), length=64, salt=salt, iterations=iterations)
    hashed = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return f"{hashed.decode()}:{salt.hex()}:{iterations}"

def verify_password(password, stored_hash):
    try:
        hashed, salt, iterations = stored_hash.split(":")
        return secure_hash_password(password, bytes.fromhex(salt), int(iterations)) == stored_hash
    except ValueError:
        return False

def check_password_pwned(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    headers = {"User-Agent": f"RutySec/{VERSION}"}
    try:
        response = requests.get(HIBP_API + prefix, headers=headers, timeout=10)
        response.raise_for_status()
        count = sum(int(line.split(':')[1]) for line in response.text.splitlines() if suffix in line)
        if count:
            logging.warning(f"Password breach detected: {count} occurrences")
            print(f"{Fore.RED}[!] Compromised in {count} breaches!{Style.RESET_ALL}")
            return True, count
        print(f"{Fore.GREEN}[+] No breaches found{Style.RESET_ALL}")
        return False, 0
    except requests.RequestException as e:
        logging.error(f"Breach check failed: {str(e)}")
        print(f"{Fore.YELLOW}[~] Breach check failed: {e}{Style.RESET_ALL}")
        return False, -1

def dictionary_attack(target_hash, algo="sha256", wordlist_path=ROCKYOU_PATH):
    hash_funcs = {"sha256": hashlib.sha256, "sha512": hashlib.sha512, "md5": hashlib.md5}
    if algo not in hash_funcs:
        print(f"{Fore.RED}[-] Unsupported algorithm. Supported: {', '.join(hash_funcs.keys())}{Style.RESET_ALL}")
        return None
    if not os.path.exists(wordlist_path):
        print(f"{Fore.RED}[!] Wordlist not found: {wordlist_path}{Style.RESET_ALL}")
        return None
    print(f"{Fore.YELLOW}[*] Dictionary attack loading...{Style.RESET_ALL}")
    total_lines = sum(1 for _ in open(wordlist_path, 'r', errors='ignore'))
    hash_func = hash_funcs[algo]
    with open(wordlist_path, "r", errors="ignore") as file:
        for i, word in enumerate(file):
            word = word.strip()
            if i % 10000 == 0:
                print(f"{Fore.CYAN}[~] Progress: {(i/total_lines)*100:.2f}% ({i}/{total_lines}){Style.RESET_ALL}", end='\r')
            if hash_func(word.encode()).hexdigest() == target_hash:
                print(f"\n{Fore.GREEN}[+] Cracked: {word}{Style.RESET_ALL}")
                logging.info(f"Dictionary attack succeeded: {word}")
                return word
    print(f"\n{Fore.RED}[-] No match found after {total_lines} attempts{Style.RESET_ALL}")
    return None

def save_to_vault(name, password, key, metadata=None):
    vault = {}
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, "rb") as f:
                vault = json.loads(decrypt_data(f.read(), key))
        except (InvalidToken, ValueError):
            logging.error("Vault decryption failed")
            raise ValueError("Vault corrupted or wrong master key")
    entry = {
        "hash": secure_hash_password(password),
        "created": datetime.now().isoformat(),
        "metadata": metadata or {}
    }
    vault[name] = entry
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypt_data(json.dumps(vault, indent=2), key))
    logging.info(f"Saved entry to vault: {name}")

def load_from_vault(name, key):
    if not os.path.exists(VAULT_FILE):
        return None
    try:
        with open(VAULT_FILE, "rb") as f:
            vault = json.loads(decrypt_data(f.read(), key))
            return vault.get(name)
    except (InvalidToken, ValueError):
        logging.error("Vault decryption failed during load")
        return None

def backup_vault():
    if os.path.exists(VAULT_FILE):
        backup_path = f"{VAULT_FILE}.{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
        shutil.copy2(VAULT_FILE, backup_path)
        logging.info(f"Vault backed up to {backup_path}")

def main():
    init()
    key = generate_master_key()
    banner = f"""
{Fore.CYAN}{art.text2art("RUTY", font="cricket")}{Style.RESET_ALL}
{Fore.BLUE}╔════════════════════════════════════════════╗{Style.RESET_ALL}
{Fore.BLUE}║ Professional password security suite      ║{Style.RESET_ALL}
{Fore.BLUE}║ Creator: C4l3bpy                          ║{Style.RESET_ALL}
{Fore.BLUE}║ Version: {VERSION} - {datetime.now().strftime('%Y-%m-%d')}     ║{Style.RESET_ALL}
{Fore.BLUE}║ Security Level: Great                 ║{Style.RESET_ALL}
{Fore.BLUE}╚════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)
    while True:
        print(f"{Fore.YELLOW}\nSecurity Operations:{Style.RESET_ALL}")
        print(f"1.{Fore.RED} Generate a secure password")
        print(f"2. {Fore.YELLOW} Hash password")
        print(f"3. {Fore.CYAN}Check password breach")
        print(f"4. {Fore.RED}Perform dictionary attack")
        print(f"5.{Fore.WHITE} Save password to vault")
        print(f"6.{Fore.MAGENTA} Retrieve from vault")
        print(f"7. {Fore.CYAN} Backup vault")
        print("8. Exit")
        choice = input(f"{Fore.CYAN}Select operation [1-8]: {Style.RESET_ALL}").strip()

        try:
            if choice == "1":
                length = int(input(f"Length (min {MIN_PASSWORD_LENGTH}): ") or MIN_PASSWORD_LENGTH)
                pwd = generate_password(max(length, MIN_PASSWORD_LENGTH))
                score = zxcvbn.zxcvbn(pwd)
                print(f"{Fore.GREEN}Password: {pwd}{Style.RESET_ALL}")
                print(f"Strength: {score['score']}/4")
                print(f"Crack Time: {score['crack_times_display']['offline_fast_hashing_1e10_per_second']}")
                logging.info("Generated new password")
            elif choice == "2":
                pwd = getpass.getpass("Password (hidden input): ")
                salt = input("Custom salt (hex, optional): ").strip()
                salt = bytes.fromhex(salt) if salt else None
                iterations = int(input(f"Iterations (default {DEFAULT_ITERATIONS}): ") or DEFAULT_ITERATIONS)
                if iterations < 1000000:
                    print(f"{Fore.YELLOW}[!] Warning: Low iterations may reduce security{Style.RESET_ALL}")
                hashed = secure_hash_password(pwd, salt, iterations)
                print(f"{Fore.GREEN}Hash: {hashed}{Style.RESET_ALL}")
                logging.info("Password hashed")
            elif choice == "3":
                pwd = getpass.getpass("Password (hidden input): ")
                is_pwned, count = check_password_pwned(pwd)
            elif choice == "4":
                hash_val = input("Target hash: ").strip()
                algo = input("Algorithm (md5/sha256/sha512): ").lower()
                wordlist = input(f"Wordlist (default {ROCKYOU_PATH}): ") or ROCKYOU_PATH
                dictionary_attack(hash_val, algo, wordlist)
            elif choice == "5":
                name = input("Entry name: ").strip()
                if not name:
                    raise ValueError("Name cannot be empty")
                pwd = getpass.getpass("Password (hidden input): ")
                metadata = {"note": input("Optional note: ").strip()}
                save_to_vault(name, pwd, key, metadata)
                print(f"{Fore.GREEN}[+] Secured in vault{Style.RESET_ALL}")
            elif choice == "6":
                name = input("Entry name: ").strip()
                if entry := load_from_vault(name, key):
                    print(f"{Fore.GREEN}Hash: {entry['hash']}{Style.RESET_ALL}")
                    print(f"Created: {entry['created']}")
                    if entry['metadata'].get('note'):
                        print(f"Note: {entry['metadata']['note']}")
                else:
                    print(f"{Fore.RED}[-] Entry not found or vault corrupted{Style.RESET_ALL}")
            elif choice == "7":
                backup_vault()
                print(f"{Fore.GREEN}[+] Vault backup created{Style.RESET_ALL}")
            elif choice == "8":
                print(f"{Fore.GREEN}[+] Shutting down securely{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}[-] Invalid selection. Choose 1-8{Style.RESET_ALL}")
        except ValueError as e:
            print(f"{Fore.RED}[-] Input error: {e}{Style.RESET_ALL}")
            logging.error(f"ValueError: {str(e)}")
        except Exception as e:
            print(f"{Fore.RED}[-] Unexpected error: {e}{Style.RESET_ALL}")
            logging.error(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    try:
        main()
    finally:
        if os.path.exists(KEY_FILE):
            os.chmod(KEY_FILE, 0o600)
        if os.path.exists(SALT_FILE):
            os.chmod(SALT_FILE, 0o600)
        logging.info("Program terminated")