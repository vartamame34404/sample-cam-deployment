# patient_crypto.py
import mysql.connector
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import datetime
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

# ---------------- Database Connection ----------------
def get_db_connection():
    mysql_url = os.getenv("MYSQL_URL")
    if not mysql_url:
        raise ValueError("MYSQL_URL environment variable not set.")

    url = urlparse(mysql_url)
    return mysql.connector.connect(
        host=url.hostname,
        port=url.port,
        user=url.username,
        password=url.password,
        database=url.path.lstrip("/")
    )

# ---------------- AES Key Derivation ----------------
def derive_key_from_dna(dna_sequence: str):
    dna_bytes = dna_sequence.encode()
    salt = b"static_salt_for_demo"  # replace with a secure random salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(dna_bytes)

# ---------------- AES Encrypt / Decrypt ----------------
def encrypt_data(plain_text: str, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_data(cipher_text: str, key: bytes):
    raw = base64.b64decode(cipher_text)
    iv = raw[:16]
    encrypted_data = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

# ---------------- Store Patient Data ----------------
def store_patient_data(patient_id, full_name, email, contact, dob, gender, address, dna_sequence):
    conn = get_db_connection()
    cursor = conn.cursor()

    key = derive_key_from_dna(dna_sequence)

    encrypted_name = encrypt_data(full_name, key)
    encrypted_email = encrypt_data(email, key)
    encrypted_contact = encrypt_data(contact, key)
    encrypted_dob = encrypt_data(dob, key)
    encrypted_gender = encrypt_data(gender, key)
    encrypted_address = encrypt_data(address, key)

    now = datetime.datetime.utcnow()

    query = """
    INSERT INTO patients (patient_id, full_name, email, contact_number, dob, gender, address, dna_sequence, created_at, updated_at)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """
    cursor.execute(query, (
        int(patient_id), encrypted_name, encrypted_email, encrypted_contact,
        encrypted_dob, encrypted_gender, encrypted_address, encrypt_data(dna_sequence, key),
        now, now
    ))
    conn.commit()
    conn.close()
    return True

# ---------------- Retrieve and Decrypt ----------------
def retrieve_and_decrypt(patient_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM patients WHERE patient_id = %s", (int(patient_id),))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    # Derive key from encrypted DNA sequence
    encrypted_dna = row["dna_sequence"]
    # Try all fields decryption
    try:
        for possible_dna in [encrypted_dna]:
            key = derive_key_from_dna(decrypt_data(encrypted_dna, derive_key_from_dna(possible_dna)))
    except Exception:
        return None

    key = derive_key_from_dna(decrypt_data(row["dna_sequence"], derive_key_from_dna(decrypt_data(row["dna_sequence"], key))))

    return {
        "full_name": decrypt_data(row["full_name"], key),
        "email": decrypt_data(row["email"], key),
        "contact_number": decrypt_data(row["contact_number"], key),
        "dob": decrypt_data(row["dob"], key),
        "gender": decrypt_data(row["gender"], key),
        "address": decrypt_data(row["address"], key),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"]
    }

# ---------------- Delete Record ----------------
def delete_patient_record(patient_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM patients WHERE patient_id = %s", (int(patient_id),))
    conn.commit()
    rows_affected = cursor.rowcount
    conn.close()
    if rows_affected > 0:
        return True, "Patient record deleted successfully."
    else:
        return False, "Patient ID not found."
