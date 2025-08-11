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

# ---------------- Environment Variables ----------------
MASTER_KEY = os.getenv("MASTER_KEY")
if not MASTER_KEY:
    raise ValueError("MASTER_KEY is not set in environment variables!")

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

# ---------------- Key Derivation ----------------
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

def get_master_aes_key():
    """Derive a 32-byte AES key from MASTER_KEY string."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"master_salt",  # different salt than DNA
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(MASTER_KEY.encode())

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

    # Step 1: Derive patient-specific AES key from DNA
    patient_key = derive_key_from_dna(dna_sequence)

    # Step 2: Encrypt patient data with patient-specific key
    encrypted_name = encrypt_data(full_name, patient_key)
    encrypted_email = encrypt_data(email, patient_key)
    encrypted_contact = encrypt_data(contact, patient_key)
    encrypted_dob = encrypt_data(dob, patient_key)
    encrypted_gender = encrypt_data(gender, patient_key)
    encrypted_address = encrypt_data(address, patient_key)

    # Step 3: Encrypt DNA with master key
    master_key = get_master_aes_key()
    encrypted_dna = encrypt_data(dna_sequence, master_key)

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

# ---------------- Retrieve and Decrypt ----------------
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

    # Step 2: Decrypt DNA using master key
    master_key = get_master_aes_key()
    try:
        dna_sequence = decrypt_data(encrypted_dna, master_key)
    except Exception:
        conn.close()
        return None

    # Step 3: Derive patient-specific AES key from DNA
    patient_key = derive_key_from_dna(dna_sequence)

    # Step 4: Get patient data
    cursor.execute("SELECT * FROM patient_data WHERE patient_id = %s", (int(patient_id),))
    data_row = cursor.fetchone()
    conn.close()

    if not data_row:
        return None

    try:
        return {
            "full_name": decrypt_data(data_row["full_name"], patient_key),
            "email": decrypt_data(data_row["email"], patient_key),
            "contact_number": decrypt_data(data_row["contact_number"], patient_key),
            "dob": decrypt_data(data_row["dob"], patient_key),
            "gender": decrypt_data(data_row["gender"], patient_key),
            "address": decrypt_data(data_row["address"], patient_key),
            "created_at": data_row["created_at"],
            "updated_at": data_row["updated_at"]
        }
    except Exception:
        return None

# ---------------- Delete Patient Record ----------------
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
