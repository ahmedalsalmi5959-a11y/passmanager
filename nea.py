import sqlite3
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import sys
import tkinter as tinker

DB_DIR = Path(__file__).parent
DB_CRED = str(DB_DIR / 'vault_cred.db')
DB_VAULT = str(DB_DIR / 'vault.db')
session = False
session_key = None
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def derive_key(password, salt):
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=Type.ID
    )


def encrypt(plaintext, key):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return (iv + ciphertext).hex()


def decrypt(hex_data, key):
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
        print('First Time Setup')
        sign_up()


def sign_up():
    print('Welcome to the offline password manager.')
    masteruser = input('Choose Master username: ').strip()
    masterpass = input('Choose Master Password: ').strip()

    if not masteruser or not masterpass:
        print('Username and Password cannot be empty. ')
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
    
    print('\nLogin')
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
                print(f"Invalid password. {attempts} attempts left.")
        else:
            attempts -= 1
            print(f"User not found. {attempts} attempts left.")
    
    print('Too many failed attempts. Exiting.')


def main_menu(vault_id):
    while session:
        print('Main Menu')
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


def select_pass(vault_id):
    with sqlite3.connect(DB_VAULT) as vault:
        cursorV = vault.cursor()
        cursorV.execute('SELECT id, website_name FROM Credentials WHERE vault_id = ?', (vault_id,))
        entries = cursorV.fetchall()

        if not entries:
            print('No saved passwords yet.')
            return

        print('\nSaved Sites')
        for entry in entries:
            print(f"  [{entry[0]}] {entry[1]}")

        search = input('\nSearch by website name (Enter to see all): ').strip().lower()
        
        cursorV.execute(
            'SELECT website_name, username_encrypted, password_encrypted FROM Credentials WHERE vault_id = ? AND LOWER(website_name) LIKE ?',
            (vault_id, f"%{search}%")
        )
        matches = cursorV.fetchall()

    if not matches:
        print('No matching entries found.')
        return

    print('\nResults')
    for site, enc_user, enc_pass in matches:
        try:
            username = decrypt(enc_user, session_key)
            password = decrypt(enc_pass, session_key)
            print(f"  Site:     {site}")
            print(f"  Username: {username}")
            print(f"  Password: {password}\n")
        except Exception:
            print(f"  Error decrypting entry for {site}.")


def add_pass(vault_id):
    site = input('Website: ').strip()
    siteuser = input('Username: ').strip()
    sitepass = input('Password: ').strip()

    if not site or not siteuser or not sitepass:
        print('All fields are required.')
        return

    enc_user = encrypt(siteuser, session_key)
    enc_pass = encrypt(sitepass, session_key)

    with sqlite3.connect(DB_VAULT) as vault:
        cursorV = vault.cursor()
        cursorV.execute(
            'INSERT INTO Credentials (vault_id, website_name, username_encrypted, password_encrypted) VALUES (?, ?, ?, ?)',
            (vault_id, site, enc_user, enc_pass)
        )
    print(f"Password for '{site}' saved.")


def delete_pass(vault_id):
    with sqlite3.connect(DB_VAULT) as vault:
        cursorV = vault.cursor()
        cursorV.execute('SELECT id, website_name FROM Credentials WHERE vault_id = ?', (vault_id,))
        entries = cursorV.fetchall()

        if not entries:
            print('Nothing to delete.')
            return

        for entry in entries:
            print(f"  [{entry[0]}] {entry[1]}")

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

#-----------------------------------GUI--------------------------------------------------

class App_sign_up(tinker.Tk):
    def __init__ (self):
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        tinker.Label(self, text='Welcome to the offline password manager.').pack()
        tinker.Label(self, text='you can only sign up once').pack()
        tinker.Label(self, text='Choose Master Username: ').pack()
        self.master_username_entry = tinker.Entry(self)
        self.master_username_entry.pack()
        tinker.Label(self, text='Choose Master Password: ').pack()
        self.master_password_entry = tinker.Entry(self, show='*')
        self.master_password_entry.pack()
        tinker.Button(self, text='sign up', command=self.sign_up).pack()
        self.msg = tinker.Label(self, text='')
        self.msg.pack()

    def sign_up(self):
        masteruser = self.master_username_entry.get().strip()
        masterpass = self.master_password_entry.get().strip()

        if not masteruser or not masterpass:
            self.msg.config(text='Username and Password cannot be empty.')
            return

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
    
        self.msg.config(text='Account created successfully!')
        self.destroy
        app = app_login()
        app.mainloop()

class app_login(tinker.Tk):
    def __init__ (self):
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        tinker.Label(self, text='Welcome to the offline password manager.').pack()
        tinker.Label(self, text='please log in').pack()
        tinker.Label(self, text='Enter your Username: ').pack()
        self.username_entry = tinker.Entry(self)
        self.username_entry.pack()
        tinker.Label(self, text='Enter your Password: ').pack()
        self.password_entry = tinker.Entry(self, show='*')
        self.password_entry.pack()
        tinker.Button(self, text='log in', command=self.login).pack()
        self.msg = tinker.Label(self, text='')
        self.msg.pack()
        self.attempts = 3

    def login(self):
        global session, session_key
    
        username = self.username_entry.get().strip()
        passwrd = self.password_entry.get().strip()

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
                self.msg.config(text='Login successful.')
                self.destroy()
                app = App_main_menu(vault_id)
                app.mainloop()
                return 
            except VerifyMismatchError:
                self.attempts -= 1
                self.msg.config(text=f"Invalid password. {self.attempts} attempts left.")
        else:
            self.attempts -= 1
            self.msg.config(text=f"User not found. {self.attempts} attempts left.")
    
        self.msg.config(text='Too many failed attempts. Exiting.')
        self.destroy()
        
class App_main_menu(tinker.Tk):
    def __init__ (self, vault_id):
        self.vault_id = vault_id
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        tinker.Label(self, text='Welcome to the offline password manager.').pack()
        tinker.Label(self, text='MAIN MENU').pack()
        tinker.Button(self, text='add password', command=self.add_password).pack()
        tinker.Button(self, text='select password', command=self.select_password).pack()
        tinker.Button(self, text='log out', command=self.log_out).pack()
        self.msg = tinker.Label(self, text='')
        self.msg.pack()
        self.timeout = 5 * 60 * 1000
        self.timer = self.after(self.timeout, self.auto_logout)

    def add_password(self):
        self.destroy()
        app = App_add_password(self.vault_id)
        app.mainloop()

    def select_password(self):
        self.destroy()
        app = App_select_password(self.vault_id)
        app.mainloop()

    def log_out(self):
        self.destroy()
        app_login().mainloop()
    
    def auto_logout(self):
        self.destroy()
        app_login().mainloop()

    def reset_timer(self):
        self.after_cancel(self.timer)
        self.timer = self.after(self.timeout, self.auto_logout)

class App_add_password(tinker.Tk):
    def __init__ (self, vault_id):        
        self.vault_id = vault_id
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        tinker.Label(self, text='Please add your password details').pack()
        tinker.Label(self, text='website: ').pack()
        self.website_entry = tinker.Entry(self)
        self.website_entry.pack()
        tinker.Label(self, text='username: ').pack()
        self.username_entry = tinker.Entry(self)
        self.username_entry.pack()
        tinker.Label(self, text='password: ').pack()
        self.password_entry = tinker.Entry(self, show='*')
        self.password_entry.pack()
        tinker.Button(self, text='add', command=self.add_pass).pack()
        tinker.Button(self, text='back', command=self.main_menu).pack()
        self.msg = tinker.Label(self, text='')
        self.msg.pack()

    def add_pass(self):
        site = self.website_entry.get().strip()
        siteuser = self.username_entry.get().strip()
        sitepass = self.password_entry.get().strip()

        if not site or not siteuser or not sitepass:
            self.msg.config(text='All fields are required.')
            return

        enc_user = encrypt(siteuser, session_key)
        enc_pass = encrypt(sitepass, session_key)

        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute(
                'INSERT INTO Credentials (vault_id, website_name, username_encrypted, password_encrypted) VALUES (?, ?, ?, ?)',
                (self.vault_id, site, enc_user, enc_pass)
            )
        self.msg.config(text=f"Password for '{site}' saved.")
        self.website_entry.delete(0, tinker.END)
        self.username_entry.delete(0, tinker.END)
        self.password_entry.delete(0, tinker.END)

    def main_menu(self):
        self.destroy()
        app = App_main_menu(self.vault_id)
        app.mainloop()

class App_select_password(tinker.Tk):
    def __init__ (self, vault_id): 
        self.vault_id = vault_id
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        tinker.Label(self, text='these are your saved passwords').pack()
        self.listbox = tinker.Listbox(self, width=40, height=10)
        self.listbox.pack()
        self.listbox.bind('<<ListboxSelect>>', self.show_details)
        self.username_var = tinker.StringVar()
        self.password_var = tinker.StringVar()
        frame1 = tinker.Frame(self)
        frame1.pack()
        tinker.Label(frame1, text='Username:').pack(side='left')
        self.username_detail = tinker.Entry(frame1, width=30, state='readonly', textvariable=self.username_var)
        self.username_detail.pack(side='left')
        frame2 = tinker.Frame(self)
        frame2.pack()
        tinker.Label(frame2, text='Password:').pack(side='left')
        self.password_detail = tinker.Entry(frame2, width=30, state='readonly', textvariable=self.password_var)
        self.password_detail.pack(side='left')
        self.load_passwords()
        tinker.Button(self, text='delete', command=self.delete_pass).pack()
        tinker.Button(self, text='back', command=self.main_menu).pack()
        self.msg = tinker.Label(self, text='')
        self.msg.pack()

    def load_passwords(self):
        self.ids = []
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute('SELECT id, website_name FROM Credentials WHERE vault_id = ?', (self.vault_id,))
            entries = cursorV.fetchall()
        for entry in entries:
            self.ids.append(entry[0])
            self.listbox.insert(tinker.END, entry[1])

    def show_details(self, event):
        selected = self.listbox.curselection()
        if not selected:
            return
        site = self.listbox.get(selected)

        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            entry_id = self.ids[selected[0]]
            cursorV.execute(
                'SELECT username_encrypted, password_encrypted FROM Credentials WHERE id = ?',
                (entry_id,)
            )
            result = cursorV.fetchone()

        if result:
            username = decrypt(result[0], session_key)
            password = decrypt(result[1], session_key)
            self.username_var.set(username)
            self.password_var.set(password)

    def delete_pass(self):
        selected = self.listbox.curselection()
        if not selected:
            self.msg.config(text='Select a site first.')
            return
        entry_id = self.ids[selected[0]]
        site = self.listbox.get(selected)
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute('DELETE FROM Credentials WHERE id = ?', (entry_id,))
        self.listbox.delete(selected)
        self.ids.pop(selected[0])
        self.username_var.set('')
        self.password_var.set('')
        self.msg.config(text=f'Deleted {site}.')

    def main_menu(self):
        self.destroy()
        app = App_main_menu(self.vault_id)
        app.mainloop()

#-----------------------------------code runner--------------------------------------------------
'''
if __name__ == '__main__':
    try:
        start_up()
    except KeyboardInterrupt:
        print('\n\nExiting safely... Goodbye!')
        sys.exit(0)'''

if __name__ == '__main__':
    if Path(DB_CRED).is_file():
        app = app_login()
    else:
        app = App_sign_up()
    app.mainloop()
