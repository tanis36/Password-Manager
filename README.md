# Password-Manager
A project for my Cryptography class, this password manager uses Python's cryptography library to encypt key-value pairs of domain names and passwords.

The HMAC of the domain is stored, while AES-GCM is used to encrypt the password and the encryption is stored.

A SQLite database is used for storage. The user can either add an entry or retrieve an existing one. For retrieval, once the domain and password are verified, the data associated will be returned.
