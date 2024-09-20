import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

def vigenere_encrypt(plaintext, key):
    key = key.upper()
    key_length = len(key)
    ciphertext = ''
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            if char.isupper():
                ciphertext += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
        else:
            ciphertext += char
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    key_length = len(key)
    plaintext = ''
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            if char.isupper():
                plaintext += chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A'))
            else:
                plaintext += chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a'))
        else:
            plaintext += char
    return plaintext

def generate_playfair_key_matrix(key):
    key = key.upper().replace('J', 'I')
    matrix = []
    used = set()
    
    for char in key:
        if char not in used and char.isalpha():
            used.add(char)
            matrix.append(char)
    
    for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if char not in used:
            matrix.append(char)
    
    return [matrix[i:i+5] for i in range(0, 25, 5)]

def playfair_encrypt_pair(pair, matrix):
    row1, col1 = divmod(matrix.index(pair[0]), 5)
    row2, col2 = divmod(matrix.index(pair[1]), 5)

    if row1 == row2:
        return matrix[row1*5 + (col1 + 1) % 5] + matrix[row2*5 + (col2 + 1) % 5]
    elif col1 == col2:
        return matrix[((row1 + 1) % 5) * 5 + col1] + matrix[((row2 + 1) % 5) * 5 + col2]
    else:
        return matrix[row1*5 + col2] + matrix[row2*5 + col1]

def playfair_decrypt_pair(pair, matrix):
    row1, col1 = divmod(matrix.index(pair[0]), 5)
    row2, col2 = divmod(matrix.index(pair[1]), 5)

    if row1 == row2:
        return matrix[row1*5 + (col1 - 1) % 5] + matrix[row2*5 + (col2 - 1) % 5]
    elif col1 == col2:
        return matrix[((row1 - 1) % 5) * 5 + col1] + matrix[((row2 - 1) % 5) * 5 + col2]
    else:
        return matrix[row1*5 + col2] + matrix[row2*5 + col1]

def prepare_text_playfair(text):
    text = text.upper().replace('J', 'I')
    prepared = ''
    i = 0
    while i < len(text):
        if text[i].isalpha():
            prepared += text[i]
            if i + 1 < len(text) and text[i] == text[i+1]:
                prepared += 'X'
            elif i + 1 < len(text):
                prepared += text[i+1]
                i += 1
            else:
                prepared += 'X'
        i += 1
    return prepared

def playfair_encrypt(plaintext, key):
    matrix = sum(generate_playfair_key_matrix(key), [])
    plaintext = prepare_text_playfair(plaintext)
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        ciphertext += playfair_encrypt_pair(plaintext[i:i+2], matrix)
    return ciphertext

def playfair_decrypt(ciphertext, key):
    matrix = sum(generate_playfair_key_matrix(key), [])
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        plaintext += playfair_decrypt_pair(ciphertext[i:i+2], matrix)
    return plaintext

def mod_inverse(matrix, mod):
    det = int(np.round(np.linalg.det(matrix)))  
    det_inv = pow(det, -1, mod)  
    adjugate_matrix = np.round(np.linalg.inv(matrix) * det).astype(int)
    matrix_inv = (det_inv * adjugate_matrix) % mod  
    return matrix_inv

def hill_encrypt(plaintext, key_matrix):
    n = key_matrix.shape[0]
    plaintext = plaintext.upper().replace(' ', '')
    plaintext = [ord(c) - ord('A') for c in plaintext]
    
    if len(plaintext) % n != 0:
        plaintext += [0] * (n - len(plaintext) % n)
    
    ciphertext = ''
    for i in range(0, len(plaintext), n):
        block = np.array(plaintext[i:i+n])
        encrypted_block = np.dot(key_matrix, block) % 26
        ciphertext += ''.join(chr(num + ord('A')) for num in encrypted_block)
    
    return ciphertext

def hill_decrypt(ciphertext, key_matrix):
    n = key_matrix.shape[0]
    ciphertext = [ord(c) - ord('A') for c in ciphertext]
    inverse_key_matrix = mod_inverse(key_matrix, 26)  

    plaintext = ''
    for i in range(0, len(ciphertext), n):
        block = np.array(ciphertext[i:i+n])
        decrypted_block = np.dot(inverse_key_matrix, block) % 26
        plaintext += ''.join(chr(num + ord('A')) for num in decrypted_block)
    
    return plaintext

def load_file():
    filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if filepath:
        with open(filepath, 'r') as file:
            text_area.delete(1.0, tk.END)
            text_area.insert(tk.END, file.read())

def save_file(content):
    filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if filepath:
        with open(filepath, 'w') as file:
            file.write(content)

def on_encrypt():
    cipher_type = cipher_var.get()
    key = key_entry.get()
    if len(key) < 12:
        messagebox.showwarning("Invalid Key", "Key must be at least 12 characters long.")
        return
    plaintext = text_area.get(1.0, tk.END).strip()
    
    if cipher_type == "Vigenere":
        ciphertext = vigenere_encrypt(plaintext, key)
    elif cipher_type == "Playfair":
        ciphertext = playfair_encrypt(plaintext, key)
    elif cipher_type == "Hill":
        key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])
        ciphertext = hill_encrypt(plaintext, key_matrix)
    else:
        messagebox.showerror("Error", "Invalid cipher type selected.")
        return
    
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, ciphertext)

def on_decrypt():
    cipher_type = cipher_var.get()
    key = key_entry.get()
    if len(key) < 12:
        messagebox.showwarning("Invalid Key", "Key must be at least 12 characters long.")
        return
    ciphertext = text_area.get(1.0, tk.END).strip()
    
    if cipher_type == "Vigenere":
        plaintext = vigenere_decrypt(ciphertext, key)
    elif cipher_type == "Playfair":
        plaintext = playfair_decrypt(ciphertext, key)
    elif cipher_type == "Hill":
        key_matrix = np.array([[6, 24, 1], [13, 16, 10], [20, 17, 15]])
        plaintext = hill_decrypt(ciphertext, key_matrix)
    else:
        messagebox.showerror("Error", "Invalid cipher type selected.")
        return
    
    text_area.delete(1.0, tk.END)
    text_area.insert(tk.END, plaintext)

root = tk.Tk()
root.title("Cipher Program")

frame = tk.Frame(root)
frame.pack(pady=10)

cipher_var = tk.StringVar(value="Vigenere")
tk.Radiobutton(frame, text="Vigenere", variable=cipher_var, value="Vigenere").pack(side=tk.LEFT)
tk.Radiobutton(frame, text="Playfair", variable=cipher_var, value="Playfair").pack(side=tk.LEFT)
tk.Radiobutton(frame, text="Hill", variable=cipher_var, value="Hill").pack(side=tk.LEFT)

key_label = tk.Label(frame, text="Key:")
key_label.pack(side=tk.LEFT, padx=5)
key_entry = tk.Entry(frame)
key_entry.pack(side=tk.LEFT, padx=5)

text_area = tk.Text(root, height=15, width=50)
text_area.pack(pady=10)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

load_button = tk.Button(button_frame, text="Load File", command=load_file)
load_button.pack(side=tk.LEFT, padx=5)
encrypt_button = tk.Button(button_frame, text="Encrypt", command=on_encrypt)
encrypt_button.pack(side=tk.LEFT, padx=5)
decrypt_button = tk.Button(button_frame, text="Decrypt", command=on_decrypt)
decrypt_button.pack(side=tk.LEFT, padx=5)

root.mainloop()
