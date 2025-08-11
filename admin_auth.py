import streamlit as st
import os
import json
import random
import smtplib
from email.message import EmailMessage
from pathlib import Path
from dotenv import load_dotenv
import io
from PIL import Image
import numpy as np
import torch
import torch.nn.functional as F
from facenet_pytorch import MTCNN, InceptionResnetV1

load_dotenv()

# Email env vars
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
MASTER_EMAIL = os.getenv("MASTER_EMAIL")

# Admin storage
ADMIN_DATA_DIR = Path("admin_data")
ADMIN_DATA_DIR.mkdir(exist_ok=True)
ADMIN_FILE = ADMIN_DATA_DIR / "admins.json"

# -----------------------
# Lazy model initialization
# -----------------------
def _get_models():
    """Lazy-load MTCNN and ResNet into session_state."""
    if "mtcnn" not in st.session_state:
        st.session_state.mtcnn = MTCNN(
            keep_all=False,
            device="cuda" if torch.cuda.is_available() else "cpu"
        )
    if "resnet" not in st.session_state:
        st.session_state.resnet = InceptionResnetV1(pretrained="vggface2").eval().to(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
    return st.session_state.mtcnn, st.session_state.resnet

# -----------------------
# Admin JSON helpers
# -----------------------
def _load_admins():
    if not ADMIN_FILE.exists():
        return []
    with open(ADMIN_FILE, "r") as f:
        return json.load(f)

def _save_admins(admins):
    with open(ADMIN_FILE, "w") as f:
        json.dump(admins, f, indent=2)

# -----------------------
# Email helpers
# -----------------------
def send_email(to_email, subject, body):
    if not (EMAIL_ADDRESS and EMAIL_PASSWORD):
        st.warning("Email credentials not configured; skipping email send.")
        return False
    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Failed to send email: {e}")
        return False

def send_master_otp():
    otp = str(random.randint(100000, 999999))
    if send_email(MASTER_EMAIL, "Master OTP for Admin Registration", f"Your OTP: {otp}"):
        return otp
    else:
        st.warning("Couldn't send master OTP email. Displaying OTP in UI for debugging.")
        st.info(f"Master OTP (debug): {otp}")
        return otp

def send_otp_to(email):
    otp = str(random.randint(100000, 999999))
    if send_email(email, "Your Admin OTP", f"Your OTP: {otp}"):
        return otp
    else:
        st.warning("Couldn't send OTP email. Displaying OTP in UI for debugging.")
        st.info(f"Admin OTP (debug): {otp}")
        return otp

# -----------------------
# Face helpers
# -----------------------
def _image_bytes_to_pil(image_bytes):
    return Image.open(io.BytesIO(image_bytes)).convert("RGB")

def _get_embedding_from_bytes(image_bytes):
    """
    Returns a 1-D numpy array embedding or None if no face detected.
    """
    mtcnn, resnet = _get_models()
    img = _image_bytes_to_pil(image_bytes)
    face_tensor = mtcnn(img)
    if face_tensor is None:
        return None
    if face_tensor.dim() == 3:
        face_tensor = face_tensor.unsqueeze(0)
    device = next(resnet.parameters()).device
    face_tensor = face_tensor.to(device)
    with torch.no_grad():
        emb = resnet(face_tensor)  # (1, 512)
    emb = emb.cpu().numpy()[0]
    emb = emb / np.linalg.norm(emb)  # normalize
    return emb

def _compare_embeddings(known_embeddings, unknown_embedding):
    """
    Compare cosine similarity between known and unknown embeddings.
    Returns (best_index, best_score)
    """
    if len(known_embeddings) == 0:
        return None, None
    known = np.vstack(known_embeddings)
    dots = known @ unknown_embedding
    best_idx = int(np.argmax(dots))
    best_score = float(dots[best_idx])
    return best_idx, best_score

# -----------------------
# UI flows
# -----------------------
def register_new_admin():
    st.subheader("Register New Admin (Face + OTP)")

    if "master_verified" not in st.session_state:
        st.session_state.master_verified = False

    if not st.session_state.master_verified:
        if "master_sent" not in st.session_state:
            if st.button("Send Master OTP"):
                st.session_state.master_otp = send_master_otp()
                st.session_state.master_sent = True
                st.success("Master OTP sent (check email).")
        else:
            otp_input = st.text_input("Enter Master OTP", type="password")
            if st.button("Verify Master OTP"):
                if otp_input and otp_input == st.session_state.get("master_otp"):
                    st.session_state.master_verified = True
                    st.success("Master verified. You can register a new admin now.")
                else:
                    st.error("Invalid master OTP.")
        return

    # After master verified
    name = st.text_input("Admin Name")
    email = st.text_input("Admin Email")

    st.write("Capture admin face using your camera below.")
    img_file = st.camera_input("Capture face (click to take photo)")

    if st.button("Capture Face and Register"):
        if not (name and email and img_file):
            st.error("Please provide name, email and capture a face image.")
            return

        image_bytes = img_file.getvalue()
        embedding = _get_embedding_from_bytes(image_bytes)
        if embedding is None:
            st.error("No face detected in the captured image. Try again.")
            return

        admins = _load_admins()
        admins.append({
            "name": name,
            "email": email,
            "face_encoding": embedding.tolist()
        })
        _save_admins(admins)
        st.success(f"Admin {name} registered successfully!")
        st.session_state.master_verified = False
        st.session_state.master_sent = False

def authenticate_admin_face(threshold: float = 0.6):
    """
    Presents UI to authenticate an admin via face + OTP.
    Returns True if successful, else False.
    """
    if st.session_state.get("admin_authenticated"):
        return True

    st.write("Admin Face Authentication")
    admins = _load_admins()
    if not admins:
        st.error("No admins registered.")
        return False

    img_file = st.camera_input("Capture face to authenticate")
    if img_file is None:
        st.info("Please capture your face image to authenticate.")
        return False

    if st.button("Verify Face"):
        image_bytes = img_file.getvalue()
        unknown_emb = _get_embedding_from_bytes(image_bytes)
        if unknown_emb is None:
            st.error("No face detected. Try again.")
            return False

        known_embeddings = [np.array(a["face_encoding"]) for a in admins]
        idx, score = _compare_embeddings(known_embeddings, unknown_emb)
        st.write(f"Best similarity score: {score:.3f}")

        if score is None or score < threshold:
            st.error("Face authentication failed (no match above threshold).")
            return False

        verified_admin = admins[idx]
        st.success(f"Face match found for admin: {verified_admin['name']} (email: {verified_admin['email']})")

        otp = send_otp_to(verified_admin["email"])
        st.session_state._last_sent_otp = otp
        st.session_state._last_verified_admin = verified_admin

        user_otp = st.text_input(f"Enter OTP sent to {verified_admin['email']}", type="password")
        if st.button("Verify OTP"):
            if user_otp == st.session_state.get("_last_sent_otp"):
                st.success("Admin authenticated successfully!")
                st.session_state.admin_authenticated = True
                st.session_state.authenticated_admin = verified_admin
                st.session_state.face_verified = True
                st.session_state.otp_verified = True
                return True

            else:
                st.error("Invalid OTP")
                return False

    return False

