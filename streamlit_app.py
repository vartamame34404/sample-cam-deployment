import streamlit as st
import os
from dotenv import load_dotenv
import mysql.connector

import admin_auth as auth
import patient_crypto as crypto

load_dotenv()

# --------------------------
# Database Connection
# --------------------------
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT")),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME"),
        )
        return conn
    except mysql.connector.Error as e:
        st.error(f"Database connection failed: {e}")
        return None


# --------------------------
# Sidebar Menu
# --------------------------
menu = st.sidebar.selectbox(
    "Select Option",
    ["Encrypt and Store", "Decrypt and View", "Register Admin", "Delete Patient Record"]
)

# --------------------------
# ENCRYPT AND STORE
# --------------------------
if menu == "Encrypt and Store":
    st.subheader("🔐 Encrypt and Store Patient Data")

    patient_id = st.text_input("Patient ID")
    full_name = st.text_input("Full Name")
    email = st.text_input("Email")
    contact = st.text_input("Contact Number")
    dob = st.date_input("Date of Birth")
    gender = st.radio("Gender", ["Male", "Female", "Other"])
    address = st.text_area("Address")
    dna_sequence = st.text_area("Enter DNA Sequence")

    if st.button("Encrypt and Save"):
        if all([patient_id, full_name, email, contact, dob, gender, address, dna_sequence]):
            try:
                success = crypto.store_patient_data(
                    patient_id, full_name, email, contact, dob.strftime("%Y-%m-%d"),
                    gender, address, dna_sequence
                )
                if success:
                    st.success("✅ Patient data encrypted and stored successfully.")
                else:
                    st.error("❌ Database error occurred during insertion.")
            except ValueError as ve:
                st.error(str(ve))
            except Exception as e:
                st.error("❌ Unexpected error: " + str(e))
        else:
            st.warning("Please fill all fields.")

# --------------------------
# DECRYPT AND VIEW
# --------------------------
elif menu == "Decrypt and View":
    st.subheader("🔓 Decrypt Patient Data")

    # Step 1: Admin face verification
    if not st.session_state.get("face_verified"):
        st.info("🔐 Admin Face Verification Required")
        if auth.authenticate_admin_face():
            st.session_state.face_verified = True
            st.rerun()

    # Step 2: OTP verification
    if st.session_state.get("face_verified") and not st.session_state.get("otp_verified"):
        st.info("📧 OTP Verification Required")
        if auth.authenticate_admin():  # Assuming you still have OTP verify in auth
            st.session_state.otp_verified = True
            st.success("✅ Multi-Factor Admin Authentication Complete")
            st.rerun()

    # Step 3: View decrypted data
    if st.session_state.get("face_verified") and st.session_state.get("otp_verified"):
        patient_id = st.text_input("Enter Patient ID")
        if patient_id:
            try:
                data = crypto.retrieve_and_decrypt(patient_id)
                if data:
                    st.success("🔓 Decrypted Patient Data:")
                    st.write("**Full Name:**", data['full_name'])
                    st.write("**Email:**", data['email'])
                    st.write("**Contact:**", data['contact_number'])
                    st.write("**DOB:**", data['dob'])
                    st.write("**Gender:**", data['gender'])
                    st.write("**Address:**", data['address'])
                    st.write("**Created At:**", data['created_at'])
                    st.write("**Updated At:**", data['updated_at'])
                else:
                    st.error("❌ Patient ID not found or decryption failed.")
            except Exception as e:
                st.error(f"❌ Decryption error: {str(e)}")
        else:
            st.warning("Please enter a valid Patient ID.")

# --------------------------
# REGISTER ADMIN
# --------------------------
elif menu == "Register Admin":
    st.subheader("🛡️ Admin Registration")

    if not st.session_state.get("otp_verified_for_registration"):
        if "otp_sent_registration" not in st.session_state:
            st.session_state.generated_otp_registration = auth.send_master_otp()
            st.session_state.otp_sent_registration = True
            st.info("OTP has been sent to the master email.")

        with st.form(key="admin_registration_otp_form"):
            user_otp = st.text_input("Enter the OTP sent to master email", type="password")
            submitted = st.form_submit_button("Verify OTP")
            if submitted:
                if user_otp == st.session_state.generated_otp_registration:
                    st.session_state.otp_verified_for_registration = True
                    del st.session_state.generated_otp_registration
                    del st.session_state.otp_sent_registration
                    st.success("✅ OTP verified. Proceed with face registration.")
                    st.rerun()
                else:
                    st.error("❌ Invalid OTP. Please try again.")

    if st.session_state.get("otp_verified_for_registration"):
        auth.register_new_admin()

# --------------------------
# DELETE PATIENT RECORD
# --------------------------
elif menu == "Delete Patient Record":
    st.subheader("🗑️ Delete Patient Data")

    # Step 1: Admin face verification
    if not st.session_state.get("face_verified"):
        st.info("🔐 Admin Face Verification Required")
        if auth.authenticate_admin_face():
            st.session_state.face_verified = True
            st.rerun()

    # Step 2: OTP verification
    if st.session_state.get("face_verified") and not st.session_state.get("otp_verified"):
        st.info("📧 OTP Verification Required")
        if auth.authenticate_admin():
            st.session_state.otp_verified = True
            st.success("✅ Multi-Factor Admin Authentication Complete")
            st.rerun()

    # Step 3: Delete record
    if st.session_state.get("face_verified") and st.session_state.get("otp_verified"):
        patient_id = st.text_input("Enter Patient ID to Delete")
        if st.button("Delete Record"):
            if not patient_id:
                st.warning("Please enter a valid Patient ID.")
            else:
                success, message = crypto.delete_patient_record(patient_id)
                if success:
                    st.success(message)
                else:
                    st.error(message)
