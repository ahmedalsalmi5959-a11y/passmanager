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
        self.msg = tkinter.Label(
            self,
            text=f'You have {self.get_password_count()} saved passwords'
)
        self.msg.pack()