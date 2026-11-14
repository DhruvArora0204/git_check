import hashlib
import os
import pickle
import sqlite3
import markupsafe

def get_user_records(db_connection, username: str):
    # 1. SQL Injection vulnerability
    cursor = db_connection.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

def execute_system_backup(directory_path: str):
    # 2. Command Injection vulnerability
    os.system("tar -czf backup.tar.gz " + directory_path)

def render_user_profile(user_input: str):
    # 3. Cross-Site Scripting (XSS) vulnerability
    return markupsafe.Markup("<div>Hello " + user_input + "</div>")

def restore_session_data(raw_payload: bytes):
    # 4. Insecure Deserialization vulnerability
    return pickle.loads(raw_payload)

def generate_checksum(data: bytes):
    # 5. Weak Cryptographic Hash vulnerability
    return hashlib.md5(data).hexdigest()
