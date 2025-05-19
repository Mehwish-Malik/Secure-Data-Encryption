import streamlit as st
import hashlib
import time
import base64
from cryptography.fernet import Fernet
import uuid

# Configurations
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
MAX_ATTEMPTS = 3
LOCK_DURATION = 10  # seconds

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "current_page" not in st.session_state:
    st.session_state.current_page = "Home"
if "last_attempt_time" not in st.session_state:
    st.session_state.last_attempt_time = 0

# Utility Functions
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey: str) -> bytes:
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_text(data: str, passkey: str) -> str:
    key = generate_key_from_passkey(passkey)
    return Fernet(key).encrypt(data.encode()).decode()

def decrypt_text(encrypted_data: str, passkey: str) -> str | None:
    try:
        key = generate_key_from_passkey(passkey)
        return Fernet(key).decrypt(encrypted_data.encode()).decode()
    except Exception:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def reset_attempts():
    st.session_state.failed_attempts = 0

def generate_data_id():
    return str(uuid.uuid4())[:8]

# App Title
st.title("🔐 SecureVault - Encrypted Notes System")

# Navigation Menu
menu = ["Home", "Store Secret", "Retrieve Secret", "Re-Login"]
choice = st.sidebar.selectbox("Navigate", menu, index=menu.index(st.session_state.current_page))
st.session_state.current_page = choice

# Lock mechanism
if st.session_state.failed_attempts >= MAX_ATTEMPTS:
    if time.time() - st.session_state.last_attempt_time < LOCK_DURATION:
        wait_time = LOCK_DURATION - int(time.time() - st.session_state.last_attempt_time)
        st.warning(f"Too many incorrect attempts. Try again in {wait_time} seconds.")
        st.stop()
    else:
        st.session_state.current_page = "Re-Login"

# Home Page
if st.session_state.current_page == "Home":
    st.write("Welcome to SecureVault. Save and retrieve encrypted notes safely using a private passkey.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("➕ Store New", use_container_width=True):
            st.session_state.current_page = "Store Secret"
            st.rerun()
    with col2:
        if st.button("🔍 Retrieve Existing", use_container_width=True):
            st.session_state.current_page = "Retrieve Secret"
            st.rerun()

# Store Page
elif st.session_state.current_page == "Store Secret":
    st.subheader("🗂️ Save a Secret")
    secret_data = st.text_area("Enter your secret note:")
    passkey = st.text_input("Choose a Passkey", type="password")
    confirm = st.text_input("Re-enter Passkey", type="password")

    if st.button("Encrypt & Store"):
        if secret_data and passkey and confirm:
            if passkey != confirm:
                st.error("Passkeys do not match.")
            else:
                enc = encrypt_text(secret_data, passkey)
                data_id = generate_data_id()
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": enc
                }
                st.success("Your secret has been securely stored.")
                st.info("Keep this ID safe to retrieve your note:")
                st.code(data_id)
        else:
            st.error("All fields are required!")

# Retrieve Page
elif st.session_state.current_page == "Retrieve Secret":
    st.subheader("🔓 Access Your Secret")
    st.info(f"Remaining attempts: {MAX_ATTEMPTS - st.session_state.failed_attempts}")
    data_id = st.text_input("Enter your Data ID:")
    passkey = st.text_input("Enter your Passkey:", type="password")

    if st.button("Decrypt"):
        if data_id and passkey:
            if data_id in st.session_state.stored_data:
                encrypted = st.session_state.stored_data[data_id]["encrypted_text"]
                result = decrypt_text(encrypted, passkey)
                if result:
                    st.success("✅ Access Granted!")
                    st.markdown("### Your Secret Note:")
                    st.code(result)
                    reset_attempts()
                else:
                    st.error(f"❌ Incorrect passkey. Attempts left: {MAX_ATTEMPTS - st.session_state.failed_attempts}")
            else:
                st.error("❌ No data found with this ID.")
        else:
            st.error("Please fill in both fields.")

# Re-Login Page
elif st.session_state.current_page == "Re-Login":
    st.subheader("🔐 Re-Authentication")
    master_key = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_key == "admin123":
            reset_attempts()
            st.success("You’ve been reauthorized.")
            st.session_state.current_page = "Home"
            st.rerun()
        else:
            st.error("❌ Wrong master password.")

# Footer
st.markdown("---")
st.caption("Built for learning purposes | SecureVault System 🔒")


st.markdown("— Created with ❤️ by Mehwish Malik")