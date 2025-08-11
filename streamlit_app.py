import streamlit as st
import mysql.connector
import os
from dotenv import load_dotenv
from pathlib import Path

# Import our updated admin authentication module
import admin_auth
import patient_crypto

load_dotenv()

# Configure Streamlit page
st.set_page_config(
    page_title="Secure Patient Data System",
    layout="centered"
)

# Database connection helper
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
            port=int(os.getenv("DB_PORT", "3306")),
        )
        return conn
    except mysql.connector.Error as e:
        st.error(f"Database connection failed: {e}")
        return None


# ---------- App Pages ----------
def page_register_admin():
    st.title("Register New Admin")
    admin_auth.register_new_admin()


def page_encrypt_patient():
    st.title("Encrypt and Store Patient Data")
    conn = get_db_connection()
    if conn is None:
        return

    with st.form("encrypt_form"):
        patient_id = st.text_input("Patient ID")
        patient_name = st.text_input("Patient Name")
        patient_data = st.text_area("Patient Data")
        submit_btn = st.form_submit_button("Encrypt & Store")

        if submit_btn:
            if not (patient_id and patient_name and patient_data):
                st.error("All fields are required.")
                return

            encrypted_data, key, iv = patient_crypto.encrypt_data(patient_data)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO patients (id, name, encrypted_data, aes_key, aes_iv) VALUES (%s, %s, %s, %s, %s)",
                (patient_id, patient_name, encrypted_data, key, iv)
            )
            conn.commit()
            conn.close()

            st.success("Patient data encrypted and stored successfully!")
            st.download_button(
                label="Download AES Key",
                data=key,
                file_name=f"{patient_id}_aes_key.bin",
                mime="application/octet-stream"
            )


def page_decrypt_patient():
    st.title("Decrypt and View Patient Data")

    # Face + OTP authentication
    if not admin_auth.authenticate_admin_face(threshold=0.6):
        return

    conn = get_db_connection()
    if conn is None:
        return

    patient_id = st.text_input("Enter Patient ID to retrieve")
    if st.button("Fetch and Decrypt"):
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM patients WHERE id = %s", (patient_id,))
        record = cursor.fetchone()
        if not record:
            st.error("No patient found with that ID.")
            return

        # Get AES key from file upload
        uploaded_key = st.file_uploader("Upload AES key file", type=["bin"])
        if uploaded_key is None:
            st.info("Please upload the AES key file for this patient.")
            return

        try:
            decrypted_text = patient_crypto.decrypt_data(
                record["encrypted_data"],
                uploaded_key.read(),
                record["aes_iv"]
            )
            st.success("Decryption successful!")
            st.write(f"**Patient Name:** {record['name']}")
            st.write(f"**Decrypted Data:** {decrypted_text}")
        except Exception as e:
            st.error(f"Decryption failed: {e}")


# ---------- Sidebar Navigation ----------
PAGES = {
    "Register Admin": page_register_admin,
    "Encrypt Patient Data": page_encrypt_patient,
    "Decrypt & View Patient Data": page_decrypt_patient,
}

st.sidebar.title("Navigation")
choice = st.sidebar.radio("Go to", list(PAGES.keys()))
PAGES[choice]()
