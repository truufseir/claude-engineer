import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import sqlite3
import utils
import os
import hashlib
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import requests
import threading
import json
import random
import string
import pyperclip  # For clipboard operations

class APIKeyManager:
    def __init__(self, master):
        self.master = master
        master.title("Local API Key Manager")

        # Set a password for viewing keys
        self.view_keys_password = "timhortons"  # IMPORTANT: Change this to a strong password!
        self.view_keys_password_salt = os.urandom(16)  # Salt for the password
        self.view_keys_password_hash = self.hash_password(self.view_keys_password, self.view_keys_password_salt)

        # Load or generate encryption key
        if not os.path.exists("secret.key"):
            utils.generate_key()
        self.encryption_key = utils.load_key()

        # Database setup
        self.conn = sqlite3.connect('api_keys.db')
        self.create_table()

        # Create tabs
        self.notebook = ttk.Notebook(master)
        self.api_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.api_tab, text='API Key Management')
        self.notebook.pack(fill='both', expand=True)

        # Add password generator to the first page (api_tab)
        self.setup_password_generator()

        # API Key Management GUI setup
        self.setup_api_tab()

    def setup_password_generator(self):
        # Password Generator section at the top of the first tab
        self.password_frame = ttk.LabelFrame(self.api_tab, text='Password Generator')
        self.password_frame.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky='ew')

        ttk.Label(self.password_frame, text='Password Length:').grid(row=0, column=0, padx=5, pady=5, sticky='e')
        self.length_entry = ttk.Entry(self.password_frame, width=10)
        self.length_entry.grid(row=0, column=1, padx=5, pady=5)
        self.length_entry.insert(0, "12")  # Default length

        self.generate_button = ttk.Button(self.password_frame, text='Generate Password', command=self.generate_password)
        self.generate_button.grid(row=0, column=2, padx=5, pady=5)

        ttk.Label(self.password_frame, text='Generated Password:').grid(row=1, column=0, padx=5, pady=5, sticky='e')
        self.password_label = ttk.Label(self.password_frame, text='')
        self.password_label.grid(row=1, column=1, columnspan=2, padx=5, pady=5, sticky='w')

    def setup_api_tab(self):
        # GUI setup for API Key Management (now starts at row 1 to accommodate password generator)
        self.label_name = ttk.Label(self.api_tab, text="Name:")
        self.label_name.grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)

        self.entry_name = ttk.Entry(self.api_tab)
        self.entry_name.grid(row=1, column=1, padx=10, pady=10)

        self.label_key = ttk.Label(self.api_tab, text="API Key:")
        self.label_key.grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)

        self.entry_key = ttk.Entry(self.api_tab, show="*")
        self.entry_key.grid(row=2, column=1, padx=10, pady=10)

        self.button_add = ttk.Button(self.api_tab, text="Add Key", command=self.add_api_key)
        self.button_add.grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)

        self.button_view = ttk.Button(self.api_tab, text="View Keys", command=self.show_password_prompt)
        self.button_view.grid(row=3, column=1, padx=10, pady=10)

        self.button_scramble = ttk.Button(self.api_tab, text="Scramble", command=None)
        self.button_scramble.grid(row=3, column=2, padx=10, pady=10)

        # Treeview for displaying keys
        self.tree = ttk.Treeview(self.api_tab, columns=("Name", "Key"), show="headings")
        self.tree.heading("Name", text="Name")
        self.tree.heading("Key", text="API Key")
        self.tree.column("Name", width=150, anchor="w")
        self.tree.column("Key", width=300, anchor="w")
        self.tree.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

        self.tree.bind("<Double-1>", self.on_double_click)

        self.button_delete = ttk.Button(self.api_tab, text="Delete Selected", command=self.delete_selected_key)
        self.button_delete.grid(row=5, column=0, columnspan=3, padx=10, pady=10)

        # GUI elements for interacting with Ollama
        self.prompt_label = ttk.Label(self.api_tab, text="Enter Prompt:")
        self.prompt_label.grid(row=6, column=0, padx=10, pady=10, sticky=tk.W)

        self.prompt_entry = ttk.Entry(self.api_tab, width=50)
        self.prompt_entry.grid(row=6, column=1, padx=10, pady=10)

        self.send_button = ttk.Button(self.api_tab, text="Send to Ollama", command=self.send_to_ollama)
        self.send_button.grid(row=6, column=2, padx=10, pady=10)

        self.response_label = ttk.Label(self.api_tab, text="Response:")
        self.response_label.grid(row=7, column=0, padx=10, pady=10, sticky=tk.W)

        self.response_text = tk.Text(self.api_tab, wrap=tk.WORD)
        self.response_text.grid(row=7, column=1, columnspan=2, padx=10, pady=10)
        self.response_text.config(state="disabled")  # Make the text widget read-only

        # Status bar for messages
        self.status_label = ttk.Label(self.api_tab, text="", anchor="w")
        self.status_label.grid(row=8, column=0, columnspan=3, sticky="ew", padx=10)

    def hash_password(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def show_password_prompt(self):
        password = simpledialog.askstring("Password", "Enter password to view keys:", show='*')
        if password:
            if self.verify_password(password):
                self.view_api_keys()
            else:
                messagebox.showerror("Error", "Incorrect password.")

    def verify_password(self, entered_password):
        entered_password_hash = self.hash_password(entered_password, self.view_keys_password_salt)
        return entered_password_hash == self.view_keys_password_hash

    def create_table(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                name TEXT UNIQUE,
                api_key BLOB
            )
        ''')
        self.conn.commit()

    def add_api_key(self):
        name = self.entry_name.get()
        api_key = self.entry_key.get()

        if not name or not api_key:
            messagebox.showerror("Error", "Please enter both name and API key.")
            return

        encrypted_api_key = utils.encrypt_message(api_key, self.encryption_key)

        try:
            cursor = self.conn.cursor()
            cursor.execute("INSERT INTO api_keys (name, api_key) VALUES (?, ?)", (name, encrypted_api_key))
            self.conn.commit()
            messagebox.showinfo("Success", "API key added successfully.")
            self.clear_entries()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "An API key with this name already exists.")

    def view_api_keys(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        cursor = self.conn.cursor()
        cursor.execute("SELECT name, api_key FROM api_keys")
        rows = cursor.fetchall()

        for row in rows:
            name = row[0]
            encrypted_api_key = row[1]
            decrypted_api_key = utils.decrypt_message(encrypted_api_key, self.encryption_key)
            self.tree.insert("", tk.END, values=(name, decrypted_api_key))

    def on_double_click(self, event):
        try:
            item = self.tree.selection()[0]
        except IndexError:
            return
        values = self.tree.item(item, 'values')

        self.temp_decrypted_api_key = values[1]

        self.view_edit_window = tk.Toplevel(self.master)
        self.view_edit_window.title("View/Edit API Key")

        ttk.Label(self.view_edit_window, text="Name:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.entry_edit_name = ttk.Entry(self.view_edit_window)
        self.entry_edit_name.insert(0, values[0])
        self.entry_edit_name.grid(row=0, column=1, padx=10, pady=10)

        ttk.Label(self.view_edit_window, text="API Key:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        self.entry_edit_key = ttk.Entry(self.view_edit_window, show="*")
        self.entry_edit_key.insert(0, values[1])
        self.entry_edit_key.grid(row=1, column=1, padx=10, pady=10)

        self.copy_button = ttk.Button(self.view_edit_window, text="Copy Key", command=self.copy_api_key)
        self.copy_button.grid(row=2, column=0, padx=10, pady=10)

        ttk.Button(self.view_edit_window, text="Update", command=lambda: self.update_api_key(values[0])).grid(row=3, column=0, padx=10, pady=10)
        ttk.Button(self.view_edit_window, text="Cancel", command=self.view_edit_window.destroy).grid(row=3, column=1, padx=10, pady=10)

    def copy_api_key(self):
        self.master.clipboard_clear()
        self.master.clipboard_append(self.temp_decrypted_api_key)
        messagebox.showinfo("Copy Key", "API key copied to clipboard")

    def update_api_key(self, old_name):
        new_name = self.entry_edit_name.get()
        new_api_key = self.entry_edit_key.get()

        if not new_name or not new_api_key:
            messagebox.showerror("Error", "Please enter both name and API key.")
            return

        encrypted_api_key = utils.encrypt_message(new_api_key, self.encryption_key)

        try:
            cursor = self.conn.cursor()
            cursor.execute("UPDATE api_keys SET name=?, api_key=? WHERE name=?", (new_name, encrypted_api_key, old_name))
            self.conn.commit()
            messagebox.showinfo("Success", "API key updated successfully.")
            self.view_edit_window.destroy()
            self.view_api_keys()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "An API key with this name already exists.")

    def delete_selected_key(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "Please select an API key to delete.")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete the selected API key?"):
            cursor = self.conn.cursor()
            for item in selected_item:
                name = self.tree.item(item, 'values')[0]
                cursor.execute("DELETE FROM api_keys WHERE name=?", (name,))
                self.tree.delete(item)
            self.conn.commit()
            messagebox.showinfo("Success", "API key(s) deleted successfully.")

    def clear_entries(self):
        self.entry_name.delete(0, tk.END)
        self.entry_key.delete(0, tk.END)

    def send_to_ollama(self):
        prompt_text = self.prompt_entry.get()
        if not prompt_text:
            messagebox.showwarning("Warning", "Please enter a prompt.")
            return

        self.update_status("Sending prompt to Ollama...")

        # Use a thread to avoid freezing the GUI
        threading.Thread(target=self.send_request_and_update_response, args=(prompt_text,), daemon=True).start()

    def send_request_and_update_response(self, prompt_text):
        try:
            # Load the available models
            models_response = requests.get("http://127.0.0.1:11434/api/tags")
            models_data = models_response.json()
            available_models = [model['name'] for model in models_data.get("models", [])]

            # Check if the specific model is available
            if "llama3.2:1b" not in available_models:
                error_message = f"'llama3.2:1b' is not available. Available models: {', '.join(available_models)}"
                self.update_response_text(error_message)
                return

            # Send request to Ollama
            response = requests.post(
                "http://127.0.0.1:11434/api/generate",
                json={
                    "model": "llama3.2:1b",
                    "prompt": prompt_text
                }
            )
            response.raise_for_status()  # Raise an exception for bad status codes

            # Process the response
            full_response_text = ""
            for line in response.iter_lines():
                if line:
                    decoded_line = line.decode('utf-8')
                    json_data = json.loads(decoded_line)
                    full_response_text += json_data.get("response", "")

            self.update_response_text(full_response_text)
            self.update_status("Response received.")

        except requests.exceptions.RequestException as e:
            self.update_response_text(f"Error communicating with Ollama: {e}")
            self.update_status("Error occurred.")
        except Exception as e:
            self.update_response_text(f"An unexpected error occurred: {e}")
            self.update_status("Error occurred.")

    def update_response_text(self, text):
        # Update the response text widget in the main thread
        self.master.after(0, lambda: self._update_response_widget(text))

    def _update_response_widget(self, text):
        # Helper method to update the response widget
        self.response_text.config(state="normal")
        self.response_text.delete("1.0", tk.END)
        self.response_text.insert(tk.END, text)
        self.response_text.config(state="disabled")

    def update_status(self, message):
        # Update the status bar in the main thread
        self.master.after(0, lambda: self.status_label.config(text=message))

    def generate_password(self):
        try:
            length = int(self.length_entry.get())
            if length < 8:
                messagebox.showwarning("Warning", "Password length should be at least 8 characters.")
                return
        except ValueError:
            messagebox.showwarning("Warning", "Please enter a valid integer for password length.")
            return

        password = self.generate_secure_password(length)
        self.password_label.config(text=password)
        pyperclip.copy(password)
        messagebox.showinfo("Success", "Password copied to clipboard.")

    def generate_secure_password(self, length):
        special_characters = "!#$%&*-_=+()[]{}<>,./|:;'\"?~^\\`@"
        characters = string.ascii_letters + string.digits + special_characters
        while True:
            password = ''.join(random.choice(characters) for _ in range(length))
            if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in special_characters for c in password)):
                return password

def main():
    root = tk.Tk()
    app = APIKeyManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()