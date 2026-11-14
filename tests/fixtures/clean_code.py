import hashlib
import sqlite3

def get_user_records_safely(db_connection, username: str):
    """Secure implementation using parameterized SQL queries."""
    cursor = db_connection.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    return cursor.fetchall()

def generate_secure_checksum(data: bytes) -> str:
    """Secure implementation using SHA-256."""
    return hashlib.sha256(data).hexdigest()
