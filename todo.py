import tkinter as tk
from tkinter import ttk

class TodoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("To-Do List")
        self.geometry("350x400")

        # Input row
        self.entry = tk.Entry(self, width=30)
        self.entry.pack(pady=10)
        self.entry.bind("<Return>", lambda e: self.add_task())  # press Enter to add

        tk.Button(self, text="Add Task", command=self.add_task).pack()

        # Task list
        self.listbox = tk.Listbox(self, width=40, height=15)
        self.listbox.pack(pady=10)

        tk.Button(self, text="Delete Selected", command=self.delete_task).pack()

        # Status label
        self.status = tk.Label(self, text="")
        self.status.pack()

    def add_task(self):
        task = self.entry.get().strip()
        if task:
            self.listbox.insert(tk.END, task)
            self.entry.delete(0, tk.END)       # clear the input box
            self.status.config(text=f'Added: "{task}"')
        else:
            self.status.config(text="Can't add empty task.")

    def delete_task(self):
        selected = self.listbox.curselection()  # returns index of selected item
        if selected:
            task = self.listbox.get(selected)
            self.listbox.delete(selected)
            self.status.config(text=f'Deleted: "{task}"')
        else:
            self.status.config(text="Select a task first.")

if __name__ == "__main__":
    app = TodoApp()
    app.mainloop()