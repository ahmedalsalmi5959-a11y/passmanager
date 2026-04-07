        self.bind_all('<Any-Button>', lambda e: self.reset_timer())


    def load_passwords(self):
        self.ids = []
        self.listbox.delete(0, tinker.END)
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
                self.listbox.insert(tinker.END, entry[1])
