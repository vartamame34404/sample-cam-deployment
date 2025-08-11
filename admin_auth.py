# admin_auth.py
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

# Email env vars (keep existing behavior)
EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
MASTER_EMAIL = os.getenv("MASTER_EMAIL")

# Admin storage
ADMIN_DATA_DIR = Path("admin_data")
ADMIN_DATA_DIR.mkdir(exist_ok=True)
ADMIN_FILE = ADMIN_DATA_DIR / "admins.json"

# Face models (singletons cached in session_state to avoid reload)
if "mtcnn" not in st.session_state:
    st.session_state.mtcnn = MTCNN(keep_all=False, device="cuda" if torch.cuda.is_available() else "cpu")
if "resnet" not in st.session_state:
    st.session_state.resnet = InceptionResnetV1(pretrained="vggface2").eval().to("cpu" if not torch.cuda.is_available() else "cuda")

def _load_admins():
    if not ADMIN_FILE.exists():
        return []
    with open(ADMIN_FILE, "r") as f:
        return json.load(f)

def _save_admins(admins):
    with open(ADMIN_FILE, "w") as f:
        json.dump(admins, f, indent=2)

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
        # If email can't be sent, still return OTP to allow local testing
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

# ---------- Face helpers ----------
def _image_bytes_to_pil(image_bytes):
    return Image.open(io.BytesIO(image_bytes)).convert("RGB")

def _get_embedding_from_bytes(image_bytes):
    """
    Returns a 1-D numpy array embedding or None if no face detected.
    """
    mtcnn = st.session_state.mtcnn
    resnet = st.session_state.resnet
    img = _image_bytes_to_pil(image_bytes)
    # mtcnn returns a torch tensor (3x160x160) or None
    face_tensor = mtcnn(img)
    if face_tensor is None:
        return None
    # ensure batch dim
    if face_tensor.dim() == 3:
        face_tensor = face_tensor.unsqueeze(0)
    device = next(resnet.parameters()).device
    face_tensor = face_tensor.to(device)
    with torch.no_grad():
        emb = resnet(face_tensor)  # (1, 512)
    emb = emb.cpu().numpy()[0]
    # normalize embedding (common practice)
    emb = emb / np.linalg.norm(emb)
    return emb

def _compare_embeddings(known_embeddings, unknown_embedding):
    """
    known_embeddings: list of lists or array (n,512)
    unknown_embedding: 1d array (512,)
    returns (best_index, best_score)
    score = cosine similarity (1 = same, -1 opposite)
    """
    if len(known_embeddings) == 0:
        return None, None
    known = np.vstack(known_embeddings)  # shape (n,512)
    # cosine similarity:
    dots = known @ unknown_embedding
    # Since we normalized embeddings, dot product == cosine similarity
    best_idx = int(np.argmax(dots))
    best_score = float(dots[best_idx])
    return best_idx, best_score

# ---------- UI flows ----------
def register_new_admin():
    st.subheader("Register New Admin (Face + OTP)")

    # Master OTP flow
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

    # After master verified:
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
        # clear master verification for future registrations
        st.session_state.master_verified = False
        st.session_state.master_sent = False

def authenticate_admin_face(threshold: float = 0.6):
    """
    Presents a small UI to authenticate an admin.
    Returns True if authentication succeeded (OTP verified),
    otherwise returns False. Uses session_state to persist result.
    """
    # If already authenticated in this session, return True
    if st.session_state.get("admin_authenticated"):
        return True

    st.write("Admin Face Authentication")
    admins = _load_admins()
    if not admins:
        st.error("No admins registered.")
        return False

    img_file = st.camera_input("Capture face to authenticate")

    if img_file is None:
        st.info("Please capture your face image using the camera input above to authenticate.")
        return False

    if st.button("Verify Face"):
        image_bytes = img_file.getvalue()
        unknown_emb = _get_embedding_from_bytes(image_bytes)
        if unknown_emb is None:
            st.error("No face detected. Try again.")
            return False

        known_embeddings = [np.array(a["face_encoding"]) for a in admins]
        idx, score = _compare_embeddings(known_embeddings, unknown_emb)
        # Score is cosine similarity (since embeddings were normalized)
        st.write(f"Best similarity score: {score:.3f}")

        if score is None or score < threshold:
            st.error("Face authentication failed (no match above threshold).")
            return False

        # matched admin
        verified_admin = admins[idx]
        st.success(f"Face match found for admin: {verified_admin['name']} (email: {verified_admin['email']})")

        # Send OTP to admin email for second factor
        otp = send_otp_to(verified_admin["email"])
        st.session_state._last_sent_otp = otp
        st.session_state._last_verified_admin = verified_admin

        # Show input for OTP
        user_otp = st.text_input(f"Enter OTP sent to {verified_admin['email']}", type="password")
        if st.button("Verify OTP"):
            if user_otp == st.session_state.get("_last_sent_otp"):
                st.success("Admin authenticated successfully!")
                st.session_state.admin_authenticated = True
                st.session_state.authenticated_admin = verified_admin
                return True
            else:
                st.error("Invalid OTP")
                return False

    return False
