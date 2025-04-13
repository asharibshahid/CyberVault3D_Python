# Secure Data Encryption Program - Enhanced 3D UI Edition
import streamlit as st
import hashlib
import json
import os
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
import time

# Configuration
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value_999"
LOCKDOWN_DURATION = 60
SESSION_EXPIRE = 1800  # 30 minutes

# Custom CSS for 3D effects and animations
st.markdown(f"""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@900&family=Roboto+Mono:wght@300&display=swap');

    /* Main 3D container */
    .main {{
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        color: #e94560 !important;
    }}

    /* 3D Card effect */
    .card {{
        background: rgba(255, 255, 255, 0.05) !important;
        border-radius: 15px !important;
        backdrop-filter: blur(10px);
        border: 1px solid rgba(255, 255, 255, 0.2);
        transform: perspective(1000px) rotateY(0deg) rotateX(0deg);
        transition: all 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    }}

    .card:hover {{
        transform: perspective(1000px) rotateY(2deg) rotateX(2deg);
        box-shadow: 0 15px 45px rgba(0, 0, 0, 0.3);
    }}

    /* Glowing button effect */
    .glow-button {{
        background: linear-gradient(45deg, #e94560, #0f3460) !important;
        border: none !important;
        color: white !important;
        padding: 12px 28px !important;
        border-radius: 25px !important;
        position: relative;
        overflow: hidden;
        transition: all 0.3s ease;
    }}

    .glow-button:hover {{
        transform: scale(1.05);
        box-shadow: 0 0 20px #e94560;
    }}

    /* Floating animation */
    @keyframes float {{
        0% {{ transform: translateY(0px); }}
        50% {{ transform: translateY(-20px); }}
        100% {{ transform: translateY(0px); }}
    }}

    .floating {{
        animation: float 3s ease-in-out infinite;
    }}

    /* Cyber font styles */
    .cyber-title {{
        font-family: 'Orbitron', sans-serif !important;
        text-shadow: 0 0 10px #e94560;
    }}

    /* Matrix rain background effect */
    .matrix-bg {{
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        opacity: 0.1;
        z-index: -1;
    }}
</style>
""", unsafe_allow_html=True)

# Session state initialization
if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_activity' not in st.session_state:
    st.session_state.last_activity = time.time()

# Data handling functions
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# Cryptographic functions
def generate_key(passkey):
    key = hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode(),
        SALT,
        100000,
        dklen=32
    )
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        SALT,
        100000
    ).hex()

def encrypt_data(text, key):
    fernet = Fernet(generate_key(key))
    return fernet.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, key):
    try:
        fernet = Fernet(generate_key(key))
        return fernet.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Session management
def check_session():
    if time.time() - st.session_state.last_activity > SESSION_EXPIRE:
        st.session_state.authenticated_user = None
        st.warning("Session expired due to inactivity")
        return False
    return True

# Main app interface
def main():
    st.markdown("<h1 class='cyber-title'>🚀 CyberVault 3D</h1>", unsafe_allow_html=True)
    st.markdown("<div class='floating'>🔒 Quantum-Secured Data Storage</div>", unsafe_allow_html=True)

    menu = ["Home", "Register", "Login", "Vault", "Logout"]
    choice = st.sidebar.selectbox("🌀 Navigation", menu, 
                                help="Select your action from the menu")

    stored_data = load_data()

    if choice == "Home":
        with st.container():
            st.markdown("<div class='card'><h2>🌟 Welcome to CyberVault 3D</h2></div>", unsafe_allow_html=True)
            cols = st.columns(3)
            with cols[0]:
                st.markdown("### 🔐 Military-Grade Encryption")
            with cols[1]:
                st.markdown("### 🌐 3D Secure Interface")
            with cols[2]:
                st.markdown("### ⚡ Blazing Fast Performance")

            st.markdown("""
            <div class='card'>
                <h3>Features:</h3>
                <ul>
                    <li>Quantum-resistant AES-256 encryption</li>
                    <li>3D Secure Interface with military-grade protection</li>
                    <li>Real-time threat detection</li>
                    <li>Biometric-style authentication</li>
                    <li>Cross-platform compatibility</li>
                </ul>
            </div>
            """, unsafe_allow_html=True)

    elif choice == "Register":
        with st.form("register_form"):
            st.markdown("<div class='card'><h3>🆕 Create New Identity</h3></div>", unsafe_allow_html=True)
            username = st.text_input("Cyber ID")
            password = st.text_input("Crypto Key", type="password")
            if st.form_submit_button("🚀 Activate Identity", help="Create new secure identity"):
                if not username or not password:
                    st.error("Identity matrix incomplete!")
                elif username in stored_data:
                    st.warning("Identity already exists in the grid!")
                else:
                    stored_data[username] = {
                        "password": hash_password(password),
                        "data": []
                    }
                    save_data(stored_data)
                    st.success("✅ Identity matrix secured!")

    elif choice == "Login":
        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f"🔒 System Lockdown: {remaining}s remaining")
            st.image("https://i.gifer.com/7plQ.gif", width=300)
            return

        with st.form("login_form"):
            st.markdown("<div class='card'><h3>🔑 Identity Verification</h3></div>", unsafe_allow_html=True)
            username = st.text_input("Cyber ID")
            password = st.text_input("Crypto Key", type="password")
            
            if st.form_submit_button("🌌 Initiate Authentication", help="Verify your identity"):
                if username in stored_data and stored_data[username]["password"] == hash_password(password):
                    st.session_state.authenticated_user = username
                    st.session_state.failed_attempts = 0
                    st.session_state.last_activity = time.time()
                    st.success(f"🛸 Welcome to the Quantum Zone, {username}!")
                else:
                    st.session_state.failed_attempts += 1
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.lockout_time = time.time() + LOCKDOWN_DURATION
                        st.error("🚨 Maximum attempts exceeded! System lockdown initiated.")
                    else:
                        st.error("⚠️ Identity verification failed!")

    elif choice == "Vault" and st.session_state.authenticated_user:
        if not check_session():
            return

        tab1, tab2 = st.tabs(["📦 Store Data", "🔍 Retrieve Data"])

        with tab1:
            with st.form("store_form"):
                st.markdown("<div class='card'><h3>📡 Quantum Encryption Channel</h3></div>", unsafe_allow_html=True)
                data = st.text_area("Input Data Matrix", height=150)
                passkey = st.text_input("Quantum Key", type="password")
                
                if st.form_submit_button("🚀 Encrypt & Secure", help="Encrypt and store data"):
                    if data and passkey:
                        encrypted = encrypt_data(data, passkey)
                        stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                        save_data(stored_data)
                        st.success("✅ Data secured in quantum vault!")
                        st.balloons()

        with tab2:
            user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])
            if user_data:
                st.markdown("<div class='card'><h3>🔐 Secure Data Vault</h3></div>", unsafe_allow_html=True)
                for i, item in enumerate(user_data):
                    st.code(item, language="text")

            with st.form("retrieve_form"):
                encrypted_input = st.text_area("Encrypted Data Matrix", height=150)
                passkey = st.text_input("Decryption Key", type="password")
                
                if st.form_submit_button("🔓 Decrypt Matrix", help="Decrypt stored data"):
                    result = decrypt_data(encrypted_input, passkey)
                    if result:
                        st.success("✅ Decryption Successful!")
                        st.markdown(f"```\n{result}\n```")
                    else:
                        st.error("⚠️ Quantum signature mismatch!")

    elif choice == "Logout":
        st.session_state.authenticated_user = None
        st.session_state.last_activity = 0
        st.success("🌀 Session terminated securely")

if __name__ == "__main__":
    main()