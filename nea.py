#--------------------imports------------------------------------------------------------
import sqlite3
from pathlib import Path
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
from datetime import datetime
from collections import deque
import tkinter as tkinter
from tkinter import ttk

#--------------------varible setup-----------------------------------------------------
DB_DIR = Path(__file__).parent
DB_CRED = str(DB_DIR / 'vault_cred.db')
DB_VAULT = str(DB_DIR / 'vault.db')
session = False
session_key = None
hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)

#--------------------fuctions-------------------------------------------------------- 

def derive_key(password, salt):
    '''this function sets up the hashing algorithm using the proper parameters'''
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
    '''fuction to encrypt data using aes-256 '''
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return (iv + ciphertext).hex()


def decrypt(hex_data, key):
    '''function to decrypt data using aes-256 '''
    raw = bytes.fromhex(hex_data)
    iv, ciphertext = raw[:16], raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode()

def sorting(ls):
    '''fuction that uses merge sort to sort a list'''
    if len(ls) <= 1:
        return ls
    mid = len(ls) // 2
    left = sorting(ls[:mid])
    right = sorting(ls[mid:])
    result = []
    i = j = 0
    while i < len(left) and j < len(right):
        if left[i][1].lower() <= right[j][1].lower():
            result.append(left[i])
            i += 1
        else:
            result.append(right[j])
            j += 1
    result.extend(left[i:])
    result.extend(right[j:])
    return result

def password_strength(password):
    '''checks the strength of a password and returns the strength'''
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if any(c.isupper() for c in password):
        score += 1
    if any(c.islower() for c in password):
        score += 1
    if any(c.isdigit() for c in password):
        score += 1
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        score += 1
    if score <= 2:
        return score, 'Weak'
    elif score <= 4:
        return score, 'Moderate'
    else:
        return score, 'Strong'

def initialise_db():
    '''creates all the tables in the database if they dont exist'''
    with sqlite3.connect(DB_CRED) as vault_cred:
        vault_cred.cursor().execute('''CREATE TABLE IF NOT EXISTS Metadata (
                            vault_id INTEGER PRIMARY KEY,
                            master_username TEXT,
                            password_hash TEXT,
                            salt TEXT)''')

    with sqlite3.connect(DB_VAULT) as vault:
        vault.cursor().execute('''CREATE TABLE IF NOT EXISTS Categories (
                           category_id INTEGER PRIMARY KEY,
                           category_name TEXT)''')
        vault.cursor().execute('''INSERT OR IGNORE INTO Categories (category_id, category_name) 
                           VALUES (1, "Social Media"), (2, "Finance"), (3, "Work"), (4, "Shopping"), (5, "Other")''')
        vault.cursor().execute('''CREATE TABLE IF NOT EXISTS Credentials (
                           id INTEGER PRIMARY KEY,
                           vault_id INTEGER,
                           website_name TEXT,
                           username_encrypted TEXT,
                           password_encrypted TEXT,
                           category_id INTEGER,
                           FOREIGN KEY (category_id) REFERENCES Categories(category_id))''')

class NavNode:
    '''linked list based navigation'''
    def __init__(self, page_name):
        self.page_name = page_name
        self.prev = None
        self.next = None

class NavHistory:
    '''tracks the navigation history using a double linked list'''
    def __init__(self):
        self.current = None

    def visit(self, page_name):
        '''adds a new page to the navigation history'''
        node = NavNode(page_name)
        if self.current:
            node.prev = self.current
            self.current.next = node
        self.current = node

    def get_history(self):
        '''returns the full path of visited pages as a list'''
        path = []
        node = self.current
        while node:
            path.append(node.page_name)
            node = node.prev
        return list(reversed(path))

    def go_back(self):
        '''moves back one page in the linked list'''
        if self.current and self.current.prev:
            self.current = self.current.prev
            return self.current.page_name
        return None

nav_history = NavHistory()

#-----------------------------------GUI--------------------------------------------------

class AppPage(tkinter.Tk):
    '''base class for all pages that require a session timeout'''
    def __init__(self):
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        self.timeout = 5 * 60 * 1000
        self.timer = self.after(self.timeout, self.auto_logout)
        self.bind_all('<Any-KeyPress>', lambda e: self.reset_timer())
        self.bind_all('<Any-Button>', lambda e: self.reset_timer())

    def reset_timer(self):
        '''resets the idle timer after an input has been made'''
        self.after_cancel(self.timer)
        self.timer = self.after(self.timeout, self.auto_logout)

    def auto_logout(self):
        '''logs out the user after the idle timer reaches 5 min'''
        global session, session_key
        session = False
        session_key = None
        self.destroy()
        app_login().mainloop()


class App_sign_up(tkinter.Tk):
    def __init__(self):
        '''sets up the windows for the sign up page '''
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        tkinter.Label(self, text='Welcome to the offline password manager.').pack()
        tkinter.Label(self, text='Create your account - this can only be done once').pack()
        tkinter.Label(self, text='Create your username: ').pack()
        self.master_username_entry = tkinter.Entry(self)
        self.master_username_entry.pack()
        tkinter.Label(self, text='Create your password: ').pack()
        self.master_password_entry = tkinter.Entry(self, show='*')
        self.master_password_entry.pack()
        tkinter.Button(self, text='sign up', command=self.sign_up).pack()
        self.msg = tkinter.Label(self, text='')
        self.msg.pack()

    def sign_up(self):
        '''function for signing up a new user '''
        masteruser = self.master_username_entry.get().strip()
        masterpass = self.master_password_entry.get().strip()

        if not masteruser or not masterpass:
            self.msg.config(text='Username and Password cannot be empty.')
            return

        hashed_pass = hasher.hash(masterpass)
        salt = os.urandom(16)

        with sqlite3.connect(DB_CRED) as vault_cred:
            cursorVC = vault_cred.cursor()
            cursorVC.execute(
                'INSERT INTO Metadata (master_username, password_hash, salt) VALUES (?, ?, ?)',
                (masteruser, hashed_pass, salt.hex())
            )

        self.msg.config(text='Account created successfully!')
        self.destroy()
        app = app_login()
        app.mainloop()


class app_login(tkinter.Tk):
    def __init__(self):
        '''sets up the window for the login page '''
        super().__init__()
        self.title('password manager')
        self.geometry('400x500')
        tkinter.Label(self, text='Welcome to the offline password manager.').pack()
        tkinter.Label(self, text='Enter your username and password to continue').pack()
        tkinter.Label(self, text='Enter your Username: ').pack()
        self.username_entry = tkinter.Entry(self)
        self.username_entry.pack()
        tkinter.Label(self, text='Enter your Password: ').pack()
        self.password_entry = tkinter.Entry(self, show='*')
        self.password_entry.pack()
        tkinter.Button(self, text='log in', command=self.login).pack()
        self.msg = tkinter.Label(self, text='')
        self.msg.pack()
        self.attempts = 3
        self.attempt_log = deque(maxlen=5)

    def login(self):
        '''fuction to allow user to log into the password manager '''
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
                self.attempt_log.append({
                    'time': datetime.now().strftime('%H:%M:%S'),
                    'username': username,
                })
                self.msg.config(text=f"Invalid password. {self.attempts} attempts left.")
                if self.attempts <= 0:
                    self.msg.config(text='Too many failed attempts.')
                    self.show_attempt_log()
                    self.destroy()
        else:
            self.attempts -= 1
            self.attempt_log.append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'username': username,
            })
            self.msg.config(text=f"User not found. {self.attempts} attempts left.")
            if self.attempts <= 0:
                self.msg.config(text='Too many failed attempts.')
                self.show_attempt_log()
                self.destroy()

    def show_attempt_log(self):
        '''empties the queue and displays all the failed attempts'''
        log_window = tkinter.Toplevel(self)
        log_window.title('Failed Login Attempts')
        tkinter.Label(log_window, text='Recent failed attempts:').pack()
        for attempt in self.attempt_log:
            tkinter.Label(log_window, text=f"[{attempt['time']}] Username tried: '{attempt['username']}'").pack()
        tkinter.Button(log_window, text='OK', command=log_window.destroy).pack()
        log_window.wait_window()


class App_main_menu(AppPage):
    def __init__(self, vault_id):
        '''sets up the window for the main menu page '''
        self.vault_id = vault_id
        super().__init__()
        tkinter.Label(self, text='Welcome to the offline password manager.').pack()
        tkinter.Label(self, text='MAIN MENU').pack()
        nav_history.visit('Main Menu')
        path = ' > '.join(nav_history.get_history())
        tkinter.Label(self, text=path, fg='grey').pack()
        tkinter.Button(self, text='add password', command=self.add_password).pack()
        tkinter.Button(self, text='select password', command=self.select_password).pack()
        tkinter.Button(self, text='log out', command=self.log_out).pack()
        self.msg = tkinter.Label(self, text=f'You have {self.get_password_count()} saved passwords')
        self.get_passwords_with_categories()
        self.msg.pack()

    def get_password_count(self):
        '''returns the number of saved passwords using aggregate SQL'''
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute('SELECT COUNT(*) FROM Credentials WHERE vault_id = ?', (self.vault_id,))
            count = cursorV.fetchone()[0]
        return count

    def get_passwords_with_categories(self):
        '''returns all passwords with their category name using a JOIN query'''
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute('''SELECT Credentials.website_name, Categories.category_name 
                            FROM Credentials 
                            JOIN Categories ON Credentials.category_id = Categories.category_id
                            WHERE Credentials.vault_id = ?''', (self.vault_id,))
            return cursorV.fetchall()

    def add_password(self):
        '''takes you to the adding a password page'''
        self.destroy()
        app = App_add_password(self.vault_id)
        app.mainloop()

    def select_password(self):
        '''takes you to select a password page'''
        self.destroy()
        app = App_select_password(self.vault_id)
        app.mainloop()

    def log_out(self):
        '''removes the window'''
        self.destroy()
        app_login().mainloop()


class App_add_password(AppPage):
    def __init__(self, vault_id):
        '''sets up the window for the adding a password page '''
        self.vault_id = vault_id
        super().__init__()
        tkinter.Label(self, text='Please add your password details').pack()
        nav_history.visit('Add Password')
        path = ' > '.join(nav_history.get_history())
        tkinter.Label(self, text=path, fg='grey').pack()
        tkinter.Label(self, text='website: ').pack()
        self.website_entry = tkinter.Entry(self)
        self.website_entry.pack()
        tkinter.Label(self, text='username: ').pack()
        self.username_entry = tkinter.Entry(self)
        self.username_entry.pack()
        tkinter.Label(self, text='password: ').pack()
        self.password_entry = tkinter.Entry(self, show='*')
        self.password_entry.pack()
        tkinter.Button(self, text='add', command=self.add_pass).pack()
        tkinter.Button(self, text='select password', command=self.go_to_select).pack()
        tkinter.Button(self, text='back', command=self.main_menu).pack()
        self.msg = tkinter.Label(self, text='')
        self.msg.pack()
        self.strength_label = tkinter.Label(self, text='')
        self.strength_label.pack()

    def add_pass(self):
        '''fuction to allow the user to add and store a password '''
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
        score, label = password_strength(sitepass)
        self.strength_label.config(text=f'Password strength: {label}')
        self.msg.config(text=f"Password for '{site}' saved.")
        self.website_entry.delete(0, tkinter.END)
        self.username_entry.delete(0, tkinter.END)
        self.password_entry.delete(0, tkinter.END)

    def auto_logout(self):
        '''overrides base auto_logout to clear the fields before logging out'''
        self.website_entry.delete(0, tkinter.END)
        self.username_entry.delete(0, tkinter.END)
        self.password_entry.delete(0, tkinter.END)
        super().auto_logout()

    def go_to_select(self):
        '''takes you to the select password page'''
        self.destroy()
        app = App_select_password(self.vault_id)
        app.mainloop()

    def main_menu(self):
        '''takes you to the main menu page'''
        nav_history.go_back()
        self.destroy()
        app = App_main_menu(self.vault_id)
        app.mainloop()


class App_select_password(AppPage):
    def __init__(self, vault_id):
        '''sets up the window for the select a password page'''
        self.vault_id = vault_id
        super().__init__()
        tkinter.Label(self, text='these are your saved passwords').pack()
        nav_history.visit('Select Password')
        path = ' > '.join(nav_history.get_history())
        tkinter.Label(self, text=path, fg='grey').pack()
        self.listbox = tkinter.Listbox(self, width=40, height=10)
        self.listbox.pack()
        self.listbox.bind('<<ListboxSelect>>', self.show_details)
        self.username_var = tkinter.StringVar()
        self.password_var = tkinter.StringVar()
        frame1 = tkinter.Frame(self)
        frame1.pack()
        tkinter.Label(frame1, text='Username:').pack(side='left')
        self.username_detail = tkinter.Entry(frame1, width=30, state='readonly', textvariable=self.username_var)
        self.username_detail.pack(side='left')
        frame2 = tkinter.Frame(self)
        frame2.pack()
        tkinter.Label(frame2, text='Password:').pack(side='left')
        self.password_detail = tkinter.Entry(frame2, width=30, state='readonly', textvariable=self.password_var)
        self.password_detail.pack(side='left')
        tkinter.Label(self, text='Search:').pack()
        self.search_entry = tkinter.Entry(self)
        self.search_entry.pack()
        self.sort_var = tkinter.StringVar()
        self.sort_dropdown = ttk.Combobox(self, textvariable=self.sort_var, state='readonly')
        self.sort_dropdown['values'] = ('A-Z', 'Z-A', 'Oldest first', 'Newest first')
        self.sort_dropdown.current(0)
        self.sort_dropdown.pack()
        self.sort_dropdown.bind('<<ComboboxSelected>>', lambda e: self.load_passwords())
        tkinter.Button(self, text='search', command=self.search).pack()
        tkinter.Button(self, text='delete', command=self.delete_pass).pack()
        tkinter.Button(self, text='undo', command=self.undo_delete).pack()
        tkinter.Button(self, text='add password', command=self.go_to_add).pack()
        tkinter.Button(self, text='back', command=self.main_menu).pack()
        self.undo_stack = []
        self.load_passwords()
        self.msg = tkinter.Label(self, text='')
        self.msg.pack()

    def load_passwords(self):
        '''function to load the stored passwords using the merge sort function'''
        self.ids = []
        self.listbox.delete(0, tkinter.END)
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute('SELECT id, website_name FROM Credentials WHERE vault_id = ?', (self.vault_id,))
            entries = cursorV.fetchall()
            sort = self.sort_var.get()
            if sort == 'A-Z':
                entries = sorting(entries)
            elif sort == 'Z-A':
                entries = sorting(entries)[::-1]
            elif sort == 'Oldest first':
                entries = sorted(entries, key=lambda x: x[0])
            elif sort == 'Newest first':
                entries = sorted(entries, key=lambda x: x[0], reverse=True)
            for entry in entries:
                self.ids.append(entry[0])
                self.listbox.insert(tkinter.END, entry[1])

    def show_details(self, event):
        '''function to allow the user to read the username and password after clicking on the selected password'''
        selected = self.listbox.curselection()
        if not selected:
            return

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

    def search(self):
        '''linear search algorithm to look for a specific password'''
        query = self.search_entry.get().strip().lower()
        self.listbox.delete(0, tkinter.END)
        self.ids = []
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute(
                'SELECT id, website_name FROM Credentials WHERE vault_id = ? AND LOWER(website_name) LIKE ?',
                (self.vault_id, f'%{query}%')
            )
            entries = cursorV.fetchall()
        for entry in entries:
            self.ids.append(entry[0])
            self.listbox.insert(tkinter.END, entry[1])

    def delete_pass(self):
        '''function to remove a password from the list of saved passwords'''
        selected = self.listbox.curselection()
        if not selected:
            self.msg.config(text='Select a site first.')
            return
        entry_id = self.ids[selected[0]]
        site = self.listbox.get(selected)
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute('SELECT id, vault_id, website_name, username_encrypted, password_encrypted FROM Credentials WHERE id = ?', (entry_id,))
            self.undo_stack.append(cursorV.fetchone())
            cursorV.execute('DELETE FROM Credentials WHERE id = ?', (entry_id,))
        self.listbox.delete(selected)
        self.ids.pop(selected[0])
        self.username_var.set('')
        self.password_var.set('')
        self.msg.config(text=f'Deleted {site}.')

    def undo_delete(self):
        if not self.undo_stack:
            self.msg.config(text='Nothing to undo.')
            return
        entry = self.undo_stack.pop()
        with sqlite3.connect(DB_VAULT) as vault:
            cursorV = vault.cursor()
            cursorV.execute(
                'INSERT INTO Credentials (id, vault_id, website_name, username_encrypted, password_encrypted) VALUES (?, ?, ?, ?, ?)',
                (entry[0], entry[1], entry[2], entry[3], entry[4])
            )
        self.load_passwords()
        self.msg.config(text=f'Restored {entry[2]}.')    

    def go_to_add(self):
        '''takes you to the add password page'''
        self.destroy()
        app = App_add_password(self.vault_id)
        app.mainloop()

    def main_menu(self):
        '''takes the user back to the main menu page'''
        nav_history.go_back()
        self.destroy()
        app = App_main_menu(self.vault_id)
        app.mainloop()

#-----------------------------------code runner--------------------------------------------------
if __name__ == '__main__':
    if Path(DB_CRED).is_file():
        initialise_db()
        app = app_login()
    else:
        initialise_db()
        app = App_sign_up()
    app.mainloop()