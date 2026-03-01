import sqlite3
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
session = False
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def start_up():
    db_path = Path(__file__).parent / 'vault_cred.db'
    if db_path.is_file():
        print('logging in')
        login()
    else:
        print('signing up')
        sign_up()


def sign_up():
    print('welcome to the offline password manager')
    print('you can only sign up once choose your login details carefuly')
    masteruser = input('username: ')
    masterpass = input('password: ')
    hashed_pass = hasher.hash(masterpass)
    vault_cred = sqlite3.connect(str(Path(__file__).parent / 'vault_cred.db'))
    vault = sqlite3.connect(str(Path(__file__).parent / 'vault.db'))
    cursorVC = vault_cred.cursor()
    cursorV = vault.cursor()

    cursorVC.execute('''CREATE TABLE IF NOT EXISTS Metadata (
                        vault_id INTEGER PRIMARY KEY,
                        master_username TEXT,
                        password_hash TEXT,
                        salt TEXT,
                        kdf_parameters TEXT)''')
    
    cursorV.execute('''CREATE TABLE IF NOT EXISTS Credentials (
                        id INTEGER PRIMARY KEY,
                        vault_id INTEGER,
                        website_name TEXT,
                        username_encrypted TEXT,
                        password_encrypted TEXT)''')
    
    cursorVC.execute('INSERT INTO Metadata (master_username, password_hash) VALUES (?, ?)', (masteruser, hashed_pass))
    vault_cred.commit()
    vault_cred.close()
    vault.commit()
    vault.close()
    main_menu()


def login():
    vault_cred = sqlite3.connect(str(Path(__file__).parent / 'vault_cred.db'))
    username = input('Enter username: ')
    passwrd = input('Enter password: ')
    cursorVC = vault_cred.cursor()
    cursorVC.execute('SELECT password_hash FROM Metadata WHERE master_username = ?', (username,))
    result = cursorVC.fetchone()

    if result:
        stored_hash = result[0]
        try:
            hasher.verify(stored_hash, passwrd)
            print('login success.')
            global session
            session = True
            vault_cred.close()
            main_menu()
        except VerifyMismatchError:
            print('invalid password.')
            vault_cred.close()
    else:
        print('username doesnt exist.')
        vault_cred.close()


def main_menu():
    while session == True:
        print('this is the main menu what would you like to do?')
        print('press "1" to select a password')
        print('press "2" to add a password')
        print('press "3" to delete a password')
        print('press "4" to log out a password')

        menu = 0
        menu = int(input())

        if menu == 1:
            select_pass()
        elif menu == 2:
            add_pass()
        elif menu == 3:
            delete_pass()
        elif menu == 4:
            log_out()


def select_pass():
    print()


def add_pass():
    print()


def delete_pass():
    print()


def log_out():
    global session
    session = False
    print('log out successful.')


start_up()