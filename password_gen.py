import tkinter as tk
import random
import string
import os
import datetime

def generate_password(length):
    special_characters = "!#$%&*-_=+()[]{}<>,./|:;'\"?~^\\`@"
    characters = string.ascii_letters + string.digits + special_characters
    while True:
        password = ''.join(random.choice(characters) for _ in range(length))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in special_characters for c in password)):
            return password

def save_to_file(username, site, password):
    # Create a unique filename with a timestamp and site name
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    sanitized_site = site.replace(' ', '_').replace('/', '_')  # Replace spaces and slashes to avoid file path issues
    filename = f'passwords_{sanitized_site}_{timestamp}.txt'
    
    # Get the list of drives to save the file to
    drive_letters = [drive1_entry.get(), drive2_entry.get(), drive3_entry.get()]

    for drive_letter in drive_letters:
        drive_letter = drive_letter.upper() + ':\\' if not drive_letter.endswith(':') else drive_letter + '\\'
        file_path = os.path.join(drive_letter, filename)
        with open(file_path, 'w') as f:
            f.write(f'Site: {site}\nUsername: {username}\nPassword: {password}\n\n')
        print(f'Password information saved to: {file_path}')

def show_password():
    length = int(length_entry.get())
    username = username_entry.get()
    site = site_entry.get()
    password = generate_password(length)
    save_to_file(username, site, password)
    password_label.config(text=password)

root = tk.Tk()
root.title("Muggle Pass")
root.geometry("600x600")  # you can adjust this value as per your requirements

length_label = tk.Label(root, text='Enter the desired password length:')
length_label.pack()

length_entry = tk.Entry(root)
length_entry.pack()

username_label = tk.Label(root, text='Enter the username:')
username_label.pack()

username_entry = tk.Entry(root)
username_entry.pack()

site_label = tk.Label(root, text='Enter the site name:')
site_label.pack()

site_entry = tk.Entry(root)
site_entry.pack()

drive1_label = tk.Label(root, text='Enter the first drive letter:')
drive1_label.pack()

drive1_entry = tk.Entry(root)
drive1_entry.pack()

drive2_label = tk.Label(root, text='Enter the second drive letter:')
drive2_label.pack()

drive2_entry = tk.Entry(root)
drive2_entry.pack()

drive3_label = tk.Label(root, text='Enter the third drive letter:')
drive3_label.pack()

drive3_entry = tk.Entry(root)
drive3_entry.pack()

generate_button = tk.Button(root, text='Generate Password', command=show_password)
generate_button.pack()

password_label = tk.Label(root, text='')
password_label.pack()

root.mainloop()
