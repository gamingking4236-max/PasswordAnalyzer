import sqlite3
import os
import hashlib
from datetime import datetime, timedelta

from utils.encryption import encrypt_password


# =========================
# DATABASE CONNECTION
# =========================

def get_connection():

    database_path = os.path.join(
        os.path.dirname(__file__),
        "password_analyzer.db"
    )

    return sqlite3.connect(database_path)


# =========================
# CREATE DATABASE TABLE
# =========================

def create_table():

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            password_hash TEXT NOT NULL,
            password_type TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            encrypted_password TEXT
        )
    """)

    # Check existing columns
    cursor.execute("""
        PRAGMA table_info(password_history)
    """)

    columns = [
        column[1]
        for column in cursor.fetchall()
    ]


    # Add expires_at if old database does not have it
    if "expires_at" not in columns:

        cursor.execute("""
            ALTER TABLE password_history
            ADD COLUMN expires_at TIMESTAMP
        """)


    # Add encrypted_password if old database does not have it
    if "encrypted_password" not in columns:

        cursor.execute("""
            ALTER TABLE password_history
            ADD COLUMN encrypted_password TEXT
        """)


    connection.commit()
    connection.close()


# =========================
# SAVE PASSWORD SECURELY
# =========================

def save_password(password, password_type):

    # -------------------------
    # SHA-256 HASH
    # -------------------------

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


    # -------------------------
    # FERNET ENCRYPTION
    # -------------------------

    encrypted_password = encrypt_password(
        password
    )


    # -------------------------
    # PASSWORD EXPIRY
    # -------------------------

    expiry_date = (
        datetime.now()
        + timedelta(days=90)
    )


    # -------------------------
    # SAVE TO DATABASE
    # -------------------------

    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO password_history
        (
            password_hash,
            password_type,
            created_at,
            expires_at,
            encrypted_password
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        password_hash,
        password_type,
        datetime.now(),
        expiry_date,
        encrypted_password
    ))


    connection.commit()
    connection.close()


# =========================
# GET PASSWORD HISTORY
# =========================

def get_password_history():

    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        SELECT
            id,
            password_hash,
            password_type,
            created_at,
            expires_at,
            encrypted_password
        FROM password_history
        ORDER BY created_at DESC
    """)


    history = cursor.fetchall()

    connection.close()

    return history


# =========================
# PASSWORD REUSE CHECK
# =========================

def is_password_reused(password):

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        SELECT id
        FROM password_history
        WHERE password_hash = ?
        LIMIT 1
    """, (
        password_hash,
    ))


    result = cursor.fetchone()

    connection.close()


    if result is not None:

        return True


    return False


# =========================
# CHECK PASSWORD EXPIRY
# =========================

def is_password_expired(password):

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        SELECT expires_at
        FROM password_history
        WHERE password_hash = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (
        password_hash,
    ))


    result = cursor.fetchone()

    connection.close()


    # Password not found
    if result is None:

        return False


    expires_at = result[0]


    # No expiry date
    if expires_at is None:

        return False


    try:

        expiry_date = datetime.fromisoformat(
            expires_at
        )

        return datetime.now() > expiry_date


    except ValueError:

        return False


# =========================
# GET PASSWORD EXPIRY DATE
# =========================

def get_password_expiry(password):

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()


    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        SELECT expires_at
        FROM password_history
        WHERE password_hash = ?
        ORDER BY created_at DESC
        LIMIT 1
    """, (
        password_hash,
    ))


    result = cursor.fetchone()

    connection.close()


    if result is None:

        return None


    return result[0]