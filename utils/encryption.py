from cryptography.fernet import Fernet
import os


# =========================
# ENCRYPTION KEY LOCATION
# =========================

KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "secret.key"
)


# =========================
# GET OR CREATE KEY
# =========================

def get_encryption_key():

    if os.path.exists(KEY_FILE):

        with open(KEY_FILE, "rb") as file:

            return file.read()


    key = Fernet.generate_key()


    with open(KEY_FILE, "wb") as file:

        file.write(key)


    return key


# =========================
# CREATE FERNET OBJECT
# =========================

def get_fernet():

    key = get_encryption_key()

    return Fernet(key)


# =========================
# ENCRYPT PASSWORD
# =========================

def encrypt_password(password):

    fernet = get_fernet()

    encrypted_password = fernet.encrypt(
        password.encode("utf-8")
    )

    return encrypted_password.decode("utf-8")


# =========================
# DECRYPT PASSWORD
# =========================

def decrypt_password(encrypted_password):

    fernet = get_fernet()

    decrypted_password = fernet.decrypt(
        encrypted_password.encode("utf-8")
    )

    return decrypted_password.decode("utf-8")