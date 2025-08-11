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
    if mysql_url:
        # Parse mysql://user:pass@host:port/db
        url = urlparse(mysql_url)
        return mysql.connector.connect(
            host=url.hostname,
            port=url.port,
            user=url.username,
            password=url.password,
            database=url.path.lstrip("/")
        )
    else:
        return mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT", 3306)),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
        )

# ---------------- AES Key Derivation ----------------
def derive_key_from_dna(dna_sequence: str):
    dna_bytes = dna_sequence.encode()
    salt = b"static_salt_for_demo"  # ⚠ Replace with secure random salt in production
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

# ---------------- Store Patient Data (Two Tables) ----------------
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
    encrypted_dna = encrypt_data(dna_sequence, key)

    now = datetime.datetime.utcnow()

    # Insert into patient_data table
    query_patient = """
    INSERT INTO patient_data 
    (patient_id, full_name, email, contact_number, dob, gender, address, created_at, updated_at)
    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """
    cursor.execute(query_patient, (
        int(patient_id), encrypted_name, encrypted_email, encrypted_contact,
        encrypted_dob, encrypted_gender, encrypted_address, now, now
    ))

    # Insert into sequence table
    query_sequence = """
    INSERT INTO sequence (patient_id, dna_sequence)
    VALUES (%s, %s)
    """
    cursor.execute(query_sequence, (int(patient_id), encrypted_dna))

    conn.commit()
    conn.close()
    return True

# ---------------- Retrieve and Decrypt (Auto DNA from sequence table) ----------------
def retrieve_and_decrypt(patient_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Step 1: Get encrypted DNA from sequence table
    cursor.execute("SELECT dna_sequence FROM sequence WHERE patient_id = %s", (int(patient_id),))
    seq_row = cursor.fetchone()
    if not seq_row:
        conn.close()
        return None

    encrypted_dna = seq_row["dna_sequence"]

    try:
        # Step 2: Temporary key from encrypted DNA
        temp_key = derive_key_from_dna(encrypted_dna)
        # Step 3: Decrypt to get original DNA
        dna_sequence = decrypt_data(encrypted_dna, temp_key)
        # Step 4: Final AES key from decrypted DNA
        key = derive_key_from_dna(dna_sequence)
    except Exception:
        conn.close()
        return None

    # Step 5: Get patient data from patient_data table
    cursor.execute("SELECT * FROM patient_data WHERE patient_id = %s", (int(patient_id),))
    data_row = cursor.fetchone()
    conn.close()

    if not data_row:
        return None

    try:
        return {
            "full_name": decrypt_data(data_row["full_name"], key),
            "email": decrypt_data(data_row["email"], key),
            "contact_number": decrypt_data(data_row["contact_number"], key),
            "dob": decrypt_data(data_row["dob"], key),
            "gender": decrypt_data(data_row["gender"], key),
            "address": decrypt_data(data_row["address"], key),
            "created_at": data_row["created_at"],
            "updated_at": data_row["updated_at"]
        }
    except Exception:
        return None

# ---------------- Delete Patient Record (Both Tables) ----------------
def delete_patient_record(patient_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    # Delete from sequence first (FK constraint safe)
    cursor.execute("DELETE FROM sequence WHERE patient_id = %s", (int(patient_id),))
    cursor.execute("DELETE FROM patient_data WHERE patient_id = %s", (int(patient_id),))
    conn.commit()
    rows_affected = cursor.rowcount
    conn.close()
    if rows_affected > 0:
        return True, "Patient record deleted successfully."
    else:
        return False, "Patient ID not found."
