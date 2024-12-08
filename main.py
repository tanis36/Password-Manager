# Necessary dependencies
import sqlite3
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# File path for SQLite database
DB = 'password_manager.db'

# Check if database exists, if not create it
if not os.path.exists(DB):
    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE KVS (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            domain_hmac BLOB NOT NULL,
                            password_encrypted BLOB NOT NULL,
                            total_users INTEGER,
                            net_worth INTEGER
                       )''')

# Load or generate HMAC and AES keys
def load_keys():
    if not os.path.exists('keys.env'):
        HMAC_KEY = os.urandom(32)
        AES_KEY = AESGCM.generate_key(bit_length=256)
        with open('keys.env', 'w') as key_file:
            key_file.write(f"HMAC_KEY={base64.b64encode(HMAC_KEY).decode()}\n")
            key_file.write(f"AES_KEY={base64.b64encode(AES_KEY).decode()}\n")
    else:
        with open('keys.env', 'r') as key_file:
            keys = dict(line.strip().split('=', 1) for line in key_file)
            HMAC_KEY = base64.b64decode(keys['HMAC_KEY'])
            AES_KEY = base64.b64decode(keys['AES_KEY'])
    
    return HMAC_KEY, AES_KEY

HMAC_KEY, AES_KEY = load_keys()

def compute_hmac(key, domain):
    """Computes the HMAC of the domain using SHA256."""
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(domain.encode('utf-8'))
    return h.finalize()

def encrypt_password(key, password):
    """Encrypts the password using AES-GCM."""
    aes = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_password = aes.encrypt(nonce, password.encode('utf-8'), None)
    return nonce + encrypted_password

def decrypt_password(key, encrypted_data):
    """Decrypts the encrypted password using AES-GCM."""
    aes = AESGCM(key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aes.decrypt(nonce, ciphertext, None).decode('utf-8')

def add_entry(domain, password, total_users, net_worth):
    """Adds a new entry to the database with the encrypted password."""
    domain_hmac = compute_hmac(HMAC_KEY, domain)
    encrypted_password = encrypt_password(AES_KEY, password)

    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('INSERT INTO KVS (domain_hmac, password_encrypted, total_users, net_worth) VALUES (?, ?, ?, ?)',
                       (domain_hmac, encrypted_password, total_users, net_worth))
        conn.commit()

def get_entry(domain, password):
    """Retrieves an entry and decrypts the password for the given domain."""
    domain_hmac = compute_hmac(HMAC_KEY, domain)

    with sqlite3.connect(DB) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT password_encrypted, total_users, net_worth FROM KVS WHERE domain_hmac = ?',
                       (domain_hmac,))
        row = cursor.fetchone()

        if row:
            encrypted_password, total_users, net_worth = row
            try:
                stored_password = decrypt_password(AES_KEY, encrypted_password)
                if stored_password == password:
                    return stored_password, total_users, net_worth
            except Exception:
                pass
    return None, None, None

def main():
    """Main loop."""
    while True:
        choice = input("1. Add Entry\n2. Get Entry\n3. Quit\nChoose an option: ")

        if choice == '1':
            domain = input("\nEnter domain name: ")
            password = input("Enter password: ")
            try:
                total_users = int(input("Enter total users: "))
                net_worth = int(input("Enter net worth: "))
            except ValueError:
                print("\nPlease enter a valid integer")
                print("------------------------------")
                continue

            add_entry(domain, password, total_users, net_worth)
            print("\nEntry added")
            print("------------------------------")

        elif choice == '2':
            domain = input("\nEnter domain name: ")
            password = input("Enter password: ")
            resulting_password, total_users, net_worth = get_entry(domain, password)

            if resulting_password:
                print(f"\nTotal Users: {total_users}")
                print(f"Net Worth: {net_worth}")
                print("------------------------------")
            else:
                print("\nDomain/Password not found.")
                print("------------------------------")

        elif choice == '3':
            break

        else:
            print("\nPlease enter a valid choice")
            print("------------------------------")

if __name__ == '__main__':
    main()