import sqlite3
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

session = False
session_key = None
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

DB_CRED = str(Path(__file__).parent / 'vault_cred.db')
DB_VAULT = str(Path(__file__).parent / 'vault.db')


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
    db_path = Path(__file__).parent / 'vault_cred.db'
    if db_path.is_file():
        print('Logging in...')
        login()
    else:
        print('First time setup...')
        sign_up()


def sign_up():
    print('Welcome to the offline password manager.')
    print('You can only sign up once — choose your login details carefully.')
    masteruser = input('Username: ')
    masterpass = input('Password: ')

    hashed_pass = hasher.hash(masterpass)
    salt = os.urandom(16)

    vault_cred = sqlite3.connect(DB_CRED)
    vault = sqlite3.connect(DB_VAULT)
    cursorVC = vault_cred.cursor()
    cursorV = vault.cursor()

    cursorVC.execute('''CREATE TABLE IF NOT EXISTS Metadata (
                        vault_id INTEGER PRIMARY KEY,
                        master_username TEXT,
                        password_hash TEXT,
                        salt TEXT)''')

    cursorV.execute('''CREATE TABLE IF NOT EXISTS Credentials (
                        id INTEGER PRIMARY KEY,
                        vault_id INTEGER,
                        website_name TEXT,
                        username_encrypted TEXT,
                        password_encrypted TEXT)''')

    cursorVC.execute(
        'INSERT INTO Metadata (master_username, password_hash, salt) VALUES (?, ?, ?)',
        (masteruser, hashed_pass, salt.hex())
    )

    vault_cred.commit()
    vault_cred.close()
    vault.commit()
    vault.close()

    print('Account created successfully.')
    login()


def login():
    global session, session_key

    vault_cred = sqlite3.connect(DB_CRED)
    cursorVC = vault_cred.cursor()

    username = input('Username: ')
    passwrd = input('Password: ')

    cursorVC.execute(
        'SELECT password_hash, salt, vault_id FROM Metadata WHERE master_username = ?',
        (username,)
    )
    result = cursorVC.fetchone()
    vault_cred.close()

    if result:
        stored_hash, salt_hex, vault_id = result
        try:
            hasher.verify(stored_hash, passwrd)
            session = True
            session_key = derive_key(passwrd, bytes.fromhex(salt_hex))
            print('Login successful.\n')
            main_menu(vault_id)
        except VerifyMismatchError:
            print('Invalid password.')
    else:
        print("Username doesn't exist.")


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
    vault = sqlite3.connect(DB_VAULT)
    cursorV = vault.cursor()

    cursorV.execute(
        'SELECT id, website_name FROM Credentials WHERE vault_id = ?',
        (vault_id,)
    )
    entries = cursorV.fetchall()

    if not entries:
        print('No saved passwords yet.')
        vault.close()
        return

    print('\n=== Saved Sites ===')
    for entry in entries:
        print(f'  [{entry[0]}] {entry[1]}')

    search = input('\nSearch by website name (or press Enter to cancel): ').strip().lower()
    if not search:
        vault.close()
        return

    cursorV.execute(
        'SELECT website_name, username_encrypted, password_encrypted FROM Credentials WHERE vault_id = ? AND LOWER(website_name) LIKE ?',
        (vault_id, f'%{search}%')
    )
    matches = cursorV.fetchall()
    vault.close()

    if not matches:
        print('No matching entries found.')
        return

    print('\n=== Results ===')
    for site, enc_user, enc_pass in matches:
        username = decrypt(enc_user, session_key)
        password = decrypt(enc_pass, session_key)
        print(f'  Site:     {site}')
        print(f'  Username: {username}')
        print(f'  Password: {password}')
        print()


def add_pass(vault_id: int):
    site = input('Website: ').strip()
    siteuser = input('Username: ').strip()
    sitepass = input('Password: ').strip()

    enc_user = encrypt(siteuser, session_key)
    enc_pass = encrypt(sitepass, session_key)

    vault = sqlite3.connect(DB_VAULT)
    cursorV = vault.cursor()
    cursorV.execute(
        'INSERT INTO Credentials (vault_id, website_name, username_encrypted, password_encrypted) VALUES (?, ?, ?, ?)',
        (vault_id, site, enc_user, enc_pass)
    )
    vault.commit()
    vault.close()
    print(f'Password for "{site}" saved.')


def delete_pass(vault_id: int):
    vault = sqlite3.connect(DB_VAULT)
    cursorV = vault.cursor()

    cursorV.execute(
        'SELECT id, website_name FROM Credentials WHERE vault_id = ?',
        (vault_id,)
    )
    entries = cursorV.fetchall()

    if not entries:
        print('No saved passwords to delete.')
        vault.close()
        return

    print('\n=== Saved Sites ===')
    for entry in entries:
        print(f'  [{entry[0]}] {entry[1]}')

    try:
        choice = int(input('\nEnter ID to delete (0 to cancel): ').strip())
    except ValueError:
        print('Invalid input.')
        vault.close()
        return

    if choice == 0:
        vault.close()
        return

    cursorV.execute(
        'DELETE FROM Credentials WHERE id = ? AND vault_id = ?',
        (choice, vault_id)
    )
    if cursorV.rowcount:
        print('Entry deleted.')
    else:
        print('No entry found with that ID.')

    vault.commit()
    vault.close()


def log_out():
    global session, session_key
    session = False
    session_key = None
    print('Logged out.')


start_up()
