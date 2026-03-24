#imports
import sqlite3
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import sys

#constants
DB_DIR = Path(__file__).parent
DB_CRED = str(DB_DIR / 'vault_cred.db')
DB_VAULT = str(DB_DIR / 'vault.db')
session = False
session_key = None
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )


def encrypt(plaintext: str, key: bytes) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return (iv + ciphertext).hex()


def decrypt(hex_data: str, key: bytes) -> str:
    raw = bytes.fromhex(hex_data)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()


def start_up():
    if Path(DB_CRED).is_file():
        login()
    else:
        print('--- First Time Setup ---')
        sign_up()


def sign_up():
    print('Welcome to the offline password manager.')
    masteruser = input('Choose Master Username: ').strip()
    masterpass = input('Choose Master Password: ').strip()

    if not masteruser or not masterpass:
        print("Username and Password cannot be empty.")
        return sign_up()

    hashed_pass = hasher.hash(masterpass)
    salt = os.urandom(16)

    with sqlite3.connect(DB_CRED) as vault_cred:
        cursorVC = vault_cred.cursor()
        cursorVC.execute('''CREATE TABLE IF NOT EXISTS Metadata (
                            vault_id INTEGER PRIMARY KEY,
                            master_username TEXT,
                            password_hash TEXT,
                            salt TEXT)''')
        cursorVC.execute(
            'INSERT INTO Metadata (master_username, password_hash, salt) VALUES (?, ?, ?)',
            (masteruser, hashed_pass, salt.hex())
        )

    with sqlite3.connect(DB_VAULT) as vault:
        cursorV = vault.cursor()
        cursorV.execute('''CREATE TABLE IF NOT EXISTS Credentials (
                            id INTEGER PRIMARY KEY,
                            vault_id INTEGER,
                            website_name TEXT,
                            username_encrypted TEXT,
                            password_encrypted TEXT)''')
    
    print('Account created successfully!\n')
    login()


def login():
    global session, session_key
    
    print('\n--- Login ---')
    attempts = 3
    while attempts > 0:
        username = input('Username: ').strip()
        passwrd = input('Password: ').strip()

        with sqlite3.connect(DB_CRED) as vault_cred:
            cursorVC = vault_cred.cursor()
            cursorVC.execute(
                'SELECT password_hash, salt, vault_id FROM Metadata WHERE master_username = ?',
                (username,)
            )
            result = cursorVC.fetchone()

        if result:
            stored_hash, salt_hex, vault_id = result
            try:
                hasher.verify(stored_hash, passwrd)
                session = True
                session_key = derive_key(passwrd, bytes.fromhex(salt_hex))
                print('Login successful.')
                main_menu(vault_id)
                return 
            except VerifyMismatchError:
                attempts -= 1
                print(f'Invalid password. {attempts} attempts left.')
        else:
            attempts -= 1
            print(f"User not found. {attempts} attempts left.")
    
    print("Too many failed attempts. Exiting.")


def main_menu(vault_id: int):
    while session:
        print('\n=== Main Menu ===')
        print('1 - View / search passwords')
        print('2 - Add a password')
        print('3 - Delete a password')
        print('4 - Log out')

        choice = input('> ').strip()

        if choice == '1':
            select_pass(vault_id)
        elif choice == '2':
            add_pass(vault_id)
        elif choice == '3':
            delete_pass(vault_id)
        elif choice == '4':
            log_out()
        else:
            print('Invalid option.')


def select_pass(vault_id: int):
    with sqlite3.connect(DB_VAULT) as vault:
        cursorV = vault.cursor()
        cursorV.execute('SELECT id, website_name FROM Credentials WHERE vault_id = ?', (vault_id,))
        entries = cursorV.fetchall()

        if not entries:
            print('No saved passwords yet.')
            return

        print('\n--- Saved Sites ---')
        for entry in entries:
            print(f'  [{entry[0]}] {entry[1]}')

        search = input('\nSearch by website name (Enter to see all): ').strip().lower()
        
        cursorV.execute(
            'SELECT website_name, username_encrypted, password_encrypted FROM Credentials WHERE vault_id = ? AND LOWER(website_name) LIKE ?',
            (vault_id, f'%{search}%')
        )
        matches = cursorV.fetchall()

    if not matches:
        print('No matching entries found.')
        return

    print('\n--- Results ---')
    for site, enc_user, enc_pass in matches:
        try:
            username = decrypt(enc_user, session_key)
            password = decrypt(enc_pass, session_key)
            print(f'  Site:     {site}')
            print(f'  Username: {username}')
            print(f'  Password: {password}\n')
        except Exception:
            print(f"  Error decrypting entry for {site}.")


def add_pass(vault_id: int):
    site = input('Website: ').strip()
    siteuser = input('Username: ').strip()
    sitepass = input('Password: ').strip()

    if not site or not siteuser or not sitepass:
        print("All fields are required.")
        return

    enc_user = encrypt(siteuser, session_key)
    enc_pass = encrypt(sitepass, session_key)

    with sqlite3.connect(DB_VAULT) as vault:
        cursorV = vault.cursor()
        cursorV.execute(
            'INSERT INTO Credentials (vault_id, website_name, username_encrypted, password_encrypted) VALUES (?, ?, ?, ?)',
            (vault_id, site, enc_user, enc_pass)
        )
    print(f'Password for "{site}" saved.')


def delete_pass(vault_id: int):
    with sqlite3.connect(DB_VAULT) as vault:
        cursorV = vault.cursor()
        cursorV.execute('SELECT id, website_name FROM Credentials WHERE vault_id = ?', (vault_id,))
        entries = cursorV.fetchall()

        if not entries:
            print('Nothing to delete.')
            return

        for entry in entries:
            print(f'  [{entry[0]}] {entry[1]}')

        try:
            choice = int(input('\nEnter ID to delete (0 to cancel): ').strip())
            if choice == 0: return
            cursorV.execute('DELETE FROM Credentials WHERE id = ? AND vault_id = ?', (choice, vault_id))
            print('Entry deleted.' if cursorV.rowcount else 'ID not found.')
        except ValueError:
            print('Invalid input.')


def log_out():
    global session, session_key
    session = False
    session_key = None
    print('Logged out.')


if __name__ == "__main__":
    try:
        start_up()
    except KeyboardInterrupt:
        print("\n\nExiting safely... Goodbye!")
        sys.exit(0)