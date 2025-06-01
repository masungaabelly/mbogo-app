import os
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from PIL import Image
import sqlite3
from sqlite3 import Error
import bcrypt
import json
import uuid
import tempfile
import qrcode
from io import BytesIO, StringIO
import base64
import hashlib
import time

# --- Configuration and Constants ---
st.set_page_config(
    page_title="CO2 Emissions Analyzer Pro",
    page_icon="🌱",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Constants
ADMIN_USERNAME = "abelmbogo"
ADMIN_NAME = "Abel Mbogo"
ADMIN_EMAIL = "masungaabel5@gmail.com"
ADMIN_WHATSAPP = "0658490848"
ADMIN_INITIAL_PASSWORD = "admin@2025"
WHATSAPP_GROUP_INVITE_LINK = "https://chat.whatsapp.com/CVsa41eRYEZ8ixI3u6et80"
SESSION_TIMEOUT = 1800  # 30 minutes
PASSWORD_MIN_LENGTH = 8
MAX_LOGIN_ATTEMPTS = 5
LOGIN_BLOCK_TIME = 300  # 5 minutes

# Paths
BASE_PATH = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_PATH, "models", "carbon_dioxide_rate.pkl")
DATA_PATH = os.path.join(BASE_PATH, "FuelConsumption.csv")
DB_PATH = os.path.join(BASE_PATH, "co2_analyzer.db")

# --- Database Setup ---
def init_database():
    """Initialize SQLite database with required tables"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                whatsapp TEXT,
                registration_number TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'normal',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                login_attempts INTEGER DEFAULT 0,
                last_attempt_time TIMESTAMP
            )
        ''')
        
        # Predictions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                engine_size REAL,
                cylinders INTEGER,
                fuel_city REAL,
                fuel_hwy REAL,
                predicted_co2 REAL,
                emission_level TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Visitor counter table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS visitor_counter (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                visit_date DATE UNIQUE,
                count INTEGER DEFAULT 0
            )
        ''')
        
        # Reports table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                report_type TEXT,
                report_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create admin user if not exists
        cursor.execute("SELECT * FROM users WHERE username = ?", (ADMIN_USERNAME,))
        if not cursor.fetchone():
            admin_password_hash = bcrypt.hashpw(ADMIN_INITIAL_PASSWORD.encode('utf-8'), bcrypt.gensalt())
            cursor.execute('''
                INSERT INTO users (username, name, email, whatsapp, password_hash, role)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ADMIN_USERNAME, ADMIN_NAME, ADMIN_EMAIL, ADMIN_WHATSAPP, admin_password_hash, 'admin'))
        
        conn.commit()
        conn.close()
        return True
    except Error as e:
        st.error(f"Database initialization error: {e}")
        return False

# --- Authentication Functions ---
def hash_password(password):
    """Hash password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(password, hashed):
    """Verify password against hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed)

def authenticate_user(username, password):
    """Authenticate user credentials"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, name, email, whatsapp, password_hash, role, is_active, 
                   login_attempts, last_attempt_time
            FROM users WHERE username = ?
        ''', (username,))
        
        user = cursor.fetchone()
        if not user:
            return None, "Invalid username or password"
        
        user_id, username, name, email, whatsapp, password_hash, role, is_active, login_attempts, last_attempt_time = user
        
        # Check if account is active
        if not is_active:
            return None, "Account is deactivated"
        
        # Check login attempts and blocking
        if login_attempts >= MAX_LOGIN_ATTEMPTS and last_attempt_time:
            last_attempt = datetime.fromisoformat(last_attempt_time)
            if datetime.now() - last_attempt < timedelta(seconds=LOGIN_BLOCK_TIME):
                return None, f"Account temporarily locked. Try again later."
        
        # Verify password
        if verify_password(password, password_hash):
            # Reset login attempts on successful login
            cursor.execute('''
                UPDATE users SET login_attempts = 0, last_login = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (user_id,))
            conn.commit()
            conn.close()
            
            return {
                'id': user_id,
                'username': username,
                'name': name,
                'email': email,
                'whatsapp': whatsapp,
                'role': role
            }, "Login successful"
        else:
            # Increment login attempts
            cursor.execute('''
                UPDATE users SET login_attempts = login_attempts + 1, 
                                last_attempt_time = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (user_id,))
            conn.commit()
            conn.close()
            return None, "Invalid username or password"
            
    except Error as e:
        return None, f"Database error: {e}"

# --- User Management Functions ---
def create_user(username, name, email, whatsapp, registration_number, password, role='normal'):
    """Create new user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        password_hash = hash_password(password)
        
        cursor.execute('''
            INSERT INTO users (username, name, email, whatsapp, registration_number, password_hash, role)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, name, email, whatsapp, registration_number, password_hash, role))
        
        conn.commit()
        conn.close()
        return True, "User created successfully"
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            return False, "Username already exists"
        elif "email" in str(e):
            return False, "Email already exists"
        elif "registration_number" in str(e):
            return False, "Registration number already exists"
        return False, str(e)
    except Error as e:
        return False, f"Database error: {e}"

def get_all_users():
    """Get all users for admin panel"""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query('''
            SELECT id, username, name, email, whatsapp, registration_number, 
                   role, created_at, last_login, is_active
            FROM users ORDER BY created_at DESC
        ''', conn)
        conn.close()
        return df
    except Error as e:
        st.error(f"Error fetching users: {e}")
        return pd.DataFrame()

def update_user_status(user_id, is_active):
    """Update user active status"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id))
        conn.commit()
        conn.close()
        return True
    except Error as e:
        st.error(f"Error updating user status: {e}")
        return False

def delete_user(user_id):
    """Delete user and related data"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM predictions WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM reports WHERE user_id = ?", (user_id,))
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        return True
    except Error as e:
        st.error(f"Error deleting user: {e}")
        return False

# --- Visitor Counter ---
def update_visitor_count():
    """Update daily visitor count"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        today = datetime.now().date()
        
        cursor.execute("SELECT count FROM visitor_counter WHERE visit_date = ?", (today,))
        result = cursor.fetchone()
        
        if result:
            cursor.execute("UPDATE visitor_counter SET count = count + 1 WHERE visit_date = ?", (today,))
        else:
            cursor.execute("INSERT INTO visitor_counter (visit_date, count) VALUES (?, 1)", (today,))
        
        conn.commit()
        conn.close()
    except Error as e:
        st.error(f"Error updating visitor count: {e}")

def get_visitor_stats():
    """Get visitor statistics"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Today's visitors
        today = datetime.now().date()
        cursor.execute("SELECT COALESCE(count, 0) FROM visitor_counter WHERE visit_date = ?", (today,))
        today_count = cursor.fetchone()[0] or 0
        
        # Total visitors
        cursor.execute("SELECT COALESCE(SUM(count), 0) FROM visitor_counter")
        total_count = cursor.fetchone()[0] or 0
        
        # This week's visitors
        week_ago = today - timedelta(days=7)
        cursor.execute("SELECT COALESCE(SUM(count), 0) FROM visitor_counter WHERE visit_date >= ?", (week_ago,))
        week_count = cursor.fetchone()[0] or 0
        
        conn.close()
        return today_count, total_count, week_count
    except Error as e:
        st.error(f"Error getting visitor stats: {e}")
        return 0, 0, 0

# --- Model and Data Loading ---
@st.cache_resource
def load_model():
    """Load the trained model with error handling"""
    try:
        if not os.path.exists(MODEL_PATH):
            st.warning(f"Model file not found at: {MODEL_PATH}")
            return None
        return joblib.load(MODEL_PATH)
    except Exception as e:
        st.error(f"Model loading error: {str(e)}")
        return None

@st.cache_data
def load_data():
    """Load the dataset with error handling"""
    try:
        if not os.path.exists(DATA_PATH):
            st.warning(f"Dataset not found at: {DATA_PATH}")
            return pd.DataFrame()
        df = pd.read_csv(DATA_PATH)
        required_columns = {'ENGINESIZE', 'CYLINDERS', 'FUELCONSUMPTION_CITY', 'FUELCONSUMPTION_HWY', 'CO2EMISSIONS'}
        if not required_columns.issubset(df.columns):
            st.warning("Dataset is missing required columns")
            return pd.DataFrame()
        return df
    except Exception as e:
        st.error(f"Data loading error: {str(e)}")
        return pd.DataFrame()

# --- Helper Functions ---
def classify_emission_level(co2_value):
    """Classify emission level with thresholds"""
    if co2_value > 250:
        return "High", "emission-high"
    elif co2_value > 150:
        return "Medium", "emission-medium"
    return "Low", "emission-low"

def get_policy_recommendations(co2_value, engine_size, cylinders):
    """Generate tailored policy recommendations"""
    policies = []
    
    if co2_value > 250:
        policies.extend([
            {
                "title": "🚨 High Emission Vehicle Restrictions",
                "content": "This vehicle would face access restrictions in urban low-emission zones.",
                "severity": "critical"
            },
            {
                "title": "🔋 Maximum EV Conversion Subsidy",
                "content": "Qualifies for 40% subsidy on electric vehicle conversion costs.",
                "severity": "positive"
            }
        ])
    elif co2_value > 200:
        policies.append({
            "title": "⛽ Enhanced Emissions Testing",
            "content": "Required to undergo emissions testing every 6 months.",
            "severity": "warning"
        })
    
    if engine_size > 3.0:
        policies.append({
            "title": "🏭 Engine Downsizing Program",
            "content": f"Eligible for tax credits when replacing this {engine_size}L engine with a smaller alternative.",
            "severity": "warning"
        })
    
    if cylinders > 6:
        policies.append({
            "title": "🔄 Cylinder Deactivation Retrofit",
            "content": f"Recommended for this {cylinders}-cylinder engine to improve efficiency during light loads.",
            "severity": "positive"
        })
    
    policies.extend([
        {
            "title": "🌱 Eco-Driving Training Program",
            "content": "Free training available that can improve fuel efficiency by 10-15%.",
            "severity": "positive"
        },
        {
            "title": "🛠️ Premium Maintenance Package",
            "content": "Recommended specialized maintenance schedule for optimal performance.",
            "severity": "positive"
        }
    ])
    
    return policies

def generate_whatsapp_qr():
    """Generate WhatsApp group QR code"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(WHATSAPP_GROUP_INVITE_LINK)
    qr.make(fit=True)
    
    qr_image = qr.make_image(fill_color="black", back_color="white")
    
    buffer = BytesIO()
    qr_image.save(buffer, format='PNG')
    buffer.seek(0)
    
    return buffer

def save_prediction(user_id, engine_size, cylinders, fuel_city, fuel_hwy, predicted_co2, emission_level):
    """Save prediction to database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO predictions (user_id, engine_size, cylinders, fuel_city, fuel_hwy, predicted_co2, emission_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, engine_size, cylinders, fuel_city, fuel_hwy, predicted_co2, emission_level))
        conn.commit()
        conn.close()
        return True
    except Error as e:
        st.error(f"Error saving prediction: {e}")
        return False

# --- CSS Styling ---
def load_css():
    st.markdown("""
    <style>
        .main-header { 
            font-size: 2.5rem; 
            color: #1E88E5; 
            text-align: center; 
            margin-bottom: 1rem;
            background: linear-gradient(45deg, #1E88E5, #4CAF50);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: bold;
        }
        .prediction-card {
            border-radius: 15px;
            padding: 25px;
            margin: 20px 0;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            box-shadow: 0 8px 16px rgba(0,0,0,0.1);
            border-left: 5px solid #1E88E5;
        }
        .policy-card { 
            border-radius: 12px;
            padding: 20px;
            margin: 15px 0;
            box-shadow: 0 6px 12px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            border-left: 4px solid #ddd;
        }
        .policy-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(0,0,0,0.15);
        }
        .policy-positive {
            background: linear-gradient(135deg, #E8F5E9, #C8E6C9);
            border-left-color: #4CAF50;
        }
        .policy-warning {
            background: linear-gradient(135deg, #FFF8E1, #FFE082);
            border-left-color: #FFC107;
        }
        .policy-critical {
            background: linear-gradient(135deg, #FFEBEE, #FFCDD2);
            border-left-color: #F44336;
        }
        .emission-high { color: #F44336; font-weight: bold; font-size: 1.1em; }
        .emission-medium { color: #FF9800; font-weight: bold; font-size: 1.1em; }
        .emission-low { color: #4CAF50; font-weight: bold; font-size: 1.1em; }
        .metric-card {
            background: linear-gradient(135deg, #ffffff, #f8f9fa);
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            border-left: 4px solid #1E88E5;
            margin: 10px 0;
        }
        .stButton>button {
            background: linear-gradient(45deg, #4CAF50, #45a049);
            color: white;
            border-radius: 8px;
            padding: 0.75rem 1.5rem;
            transition: all 0.3s ease;
            border: none;
            font-weight: 600;
        }
        .stButton>button:hover {
            background: linear-gradient(45deg, #45a049, #4CAF50);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(76, 175, 80, 0.3);
        }
        .login-container {
            max-width: 400px;
            margin: 0 auto;
            padding: 40px;
            background: linear-gradient(135deg, #ffffff, #f8f9fa);
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .admin-section {
            background: linear-gradient(135deg, #FFF3E0, #FFE0B2);
            padding: 20px;
            border-radius: 12px;
            border-left: 5px solid #FF9800;
            margin: 10px 0;
        }
        .user-role-admin { background-color: #FFEBEE; color: #D32F2F; }
        .user-role-medium { background-color: #E3F2FD; color: #1976D2; }
        .user-role-normal { background-color: #E8F5E9; color: #388E3C; }
        .sidebar-info {
            background: linear-gradient(135deg, #E3F2FD, #BBDEFB);
            padding: 15px;
            border-radius: 10px;
            margin: 10px 0;
        }
    </style>
    """, unsafe_allow_html=True)

# --- Main Application ---
def main():
    # Initialize database
    if not init_database():
        st.error("Failed to initialize database. Please check file permissions.")
        return
    
    # Load CSS
    load_css()
    
    # Update visitor count
    if 'visitor_counted' not in st.session_state:
        update_visitor_count()
        st.session_state.visitor_counted = True
    
    # Session management
    if 'user' not in st.session_state:
        st.session_state.user = None
        st.session_state.login_time = None
    
    # Check session timeout
    if st.session_state.user and st.session_state.login_time:
        if time.time() - st.session_state.login_time > SESSION_TIMEOUT:
            st.session_state.user = None
            st.session_state.login_time = None
            st.warning("Session expired. Please login again.")
    
    # Login/Registration Page
    if not st.session_state.user:
        show_login_page()
    else:
        show_main_app()

def show_login_page():
    """Display login and registration page"""
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("<h1 class='main-header'>🌱 CO2 Emissions Analyzer Pro</h1>", unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Register"])
        
        with tab1:
            st.markdown("<div class='login-container'>", unsafe_allow_html=True)
            
            with st.form("login_form"):
                st.subheader("Login to Your Account")
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                
                if st.form_submit_button("Login", use_container_width=True):
                    if username and password:
                        user, message = authenticate_user(username, password)
                        if user:
                            st.session_state.user = user
                            st.session_state.login_time = time.time()
                            st.success(message)
                            st.rerun()
                        else:
                            st.error(message)
                    else:
                        st.error("Please enter both username and password")
            
            st.markdown("</div>", unsafe_allow_html=True)
        
        with tab2:
            st.markdown("<div class='login-container'>", unsafe_allow_html=True)
            
            with st.form("register_form"):
                st.subheader("Create New Account")
                
                col1, col2 = st.columns(2)
                with col1:
                    reg_username = st.text_input("Username*")
                    reg_name = st.text_input("Full Name*")
                    reg_email = st.text_input("Email*")
                
                with col2:
                    reg_whatsapp = st.text_input("WhatsApp Number")
                    reg_number = st.text_input("Registration Number")
                    reg_password = st.text_input("Password*", type="password")
                
                reg_password_confirm = st.text_input("Confirm Password*", type="password")
                
                if st.form_submit_button("Register", use_container_width=True):
                    if not all([reg_username, reg_name, reg_email, reg_password, reg_password_confirm]):
                        st.error("Please fill in all required fields")
                    elif len(reg_password) < PASSWORD_MIN_LENGTH:
                        st.error(f"Password must be at least {PASSWORD_MIN_LENGTH} characters long")
                    elif reg_password != reg_password_confirm:
                        st.error("Passwords do not match")
                    else:
                        success, message = create_user(
                            reg_username, reg_name, reg_email, reg_whatsapp, 
                            reg_number, reg_password
                        )
                        if success:
                            st.success(message)
                            st.info("Please login with your new credentials")
                        else:
                            st.error(message)
            
            st.markdown("</div>", unsafe_allow_html=True)

def show_main_app():
    """Display main application interface"""
    # Sidebar with user info and navigation
    with st.sidebar:
        st.markdown(f"""
        <div class='sidebar-info'>
            <h3>Welcome, {st.session_state.user['name']}!</h3>
            <p><strong>Role:</strong> <span class='user-role-{st.session_state.user['role']}'>{st.session_state.user['role'].title()}</span></p>
            <p><strong>Username:</strong> {st.session_state.user['username']}</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Visitor stats
        today_visitors, total_visitors, week_visitors = get_visitor_stats()
        st.markdown(f"""
        <div class='metric-card'>
            <h4>📊 Visitor Statistics</h4>
            <p>Today: <strong>{today_visitors}</strong></p>
            <p>This Week: <strong>{week_visitors}</strong></p>
            <p>Total: <strong>{total_visitors}</strong></p>
        </div>
        """, unsafe_allow_html=True)
        
        # WhatsApp QR Code
        st.markdown("### 📱 Join WhatsApp Group")
        qr_buffer = generate_whatsapp_qr()
        st.image(qr_buffer, caption="Scan to join WhatsApp group", width=200)
        st.markdown(f"[Direct Link]({WHATSAPP_GROUP_INVITE_LINK})")
        
        # Logout button
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.user = None
            st.session_state.login_time = None
            st.rerun()
    
    # Main content area
    st.markdown("<h1 class='main-header'>🌱 CO2 Emissions Analyzer Pro</h1>", unsafe_allow_html=True)
    
    # Navigation tabs based on user role
    if st.session_state.user['role'] == 'admin':
        tabs = st.tabs(["🚗 Predictions", "📊 My History", "📈 Data Explorer", "📋 Reports", "👥 User Management", "📊 Analytics"])
        show_prediction_tab(tabs[0])
        show_history_tab(tabs[1])
        show_data_explorer_tab(tabs[2])
        show_reports_tab(tabs[3])
        show_user_management_tab(tabs[4])
        show_analytics_tab(tabs[5])
    elif st.session_state.user['role'] == 'medium':
        tabs = st.tabs(["🚗 Predictions", "📊 My History", "📈 Data Explorer", "📋 Reports"])
        show_prediction_tab(tabs[0])
        show_history_tab(tabs[1])
        show_data_explorer_tab(tabs[2])
        show_reports_tab(tabs[3])
    else:
        tabs = st.tabs(["🚗 Predictions", "📊 My History", "📈 Data Explorer"])
        show_prediction_tab(tabs[0])
        show_history_tab(tabs[1])
        show_data_explorer_tab(tabs[2])

def show_prediction_tab(tab):
    """Display prediction interface"""
    with tab:
        st.header("Vehicle Emission Prediction")
        
        model = load_model()
        if not model:
            st.error("Prediction model not available")
            return
        
        with st.expander("ℹ️ How to use", expanded=True):
            st.write("""
            Adjust the vehicle parameters using the sliders and inputs below, then click 
            'Predict CO2 Emissions' to get the estimated emissions and policy recommendations.
            """)
        
        with st.form("prediction_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                engine_size = st.slider("Engine Size (Liters)", 1.0, 8.0, 2.4, 0.1)
                cylinders = st.selectbox("Number of Cylinders", [3, 4, 5, 6, 8, 10, 12], index=2)
            
            with col2:
                fuel_city = st.number_input("City Fuel Consumption (L/100km)", 3.0, 30.0, 9.5, 0.1)
                fuel_hwy = st.number_input("Highway Fuel Consumption (L/100km)", 3.0, 25.0, 7.5, 0.1)
            
            submitted = st.form_submit_button("Predict CO2 Emissions", type="primary", use_container_width=True)
        
        if submitted:
            with st.spinner("Calculating emissions..."):
                try:
                    input_data = np.array([[engine_size, cylinders, fuel_city, fuel_hwy]])
                    prediction = model.predict(input_data)
                    predicted_co2 = float(prediction[0])
                    level, level_class = classify_emission_level(predicted_co2)
                    
                    # Display results
                    st.markdown(f"""
                    <div class='prediction-card'>
                        <h3>🎯 Prediction Results</h3>
                        <p><strong>Estimated CO2 Emissions:</strong> <span class='{level_class}'>{predicted_co2:.1f} g/km</span></p>
                        <p><strong>Emission Level:</strong> <span class='{level_class}'>{level}</span></p>
                        <p><small>📅 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small></p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Policy recommendations
                    st.subheader("📋 Recommended Policies & Actions")
                    policies = get_policy_recommendations(predicted_co2, engine_size, cylinders)
                    
                    for policy in policies:
                        st.markdown(f"""
                        <div class='policy-card policy-{policy["severity"]}'>
                            <h4>{policy["title"]}</h4>
                            <p>{policy["content"]}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    
                    # Save prediction
                    save_prediction(
                        st.session_state.user['id'], engine_size, cylinders, 
                        fuel_city, fuel_hwy, predicted_co2, level
                    )
                    
                    st.success("✅ Prediction completed and saved!")
                    
                except Exception as e:
                    st.error(f"❌ Prediction failed: {str(e)}")

def show_history_tab(tab):
    """Display user's prediction history"""
    with tab:
        st.header("📊 Your Prediction History")
        
        try:
            conn = sqlite3.connect(DB_PATH)
            df = pd.read_sql_query('''
                SELECT engine_size, cylinders, fuel_city, fuel_hwy, predicted_co2, 
                       emission_level, created_at
                FROM predictions 
                WHERE user_id = ? 
                ORDER BY created_at DESC
            ''', conn, params=(st.session_state.user['id'],))
            conn.close()
            
            if df.empty:
                st.info("📝 No predictions made yet. Use the Predictions tab to get started.")
                return
            
            # Display statistics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>Total Predictions</h4>
                    <h2>{len(df)}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                avg_co2 = df['predicted_co2'].mean()
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>Average CO2</h4>
                    <h2>{avg_co2:.1f} g/km</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                max_co2 = df['predicted_co2'].max()
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>Highest CO2</h4>
                    <h2>{max_co2:.1f} g/km</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                min_co2 = df['predicted_co2'].min()
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>Lowest CO2</h4>
                    <h2>{min_co2:.1f} g/km</h2>
                </div>
                """, unsafe_allow_html=True)
            
            # Data table
            st.subheader("📋 Detailed History")
            st.dataframe(
                df.style.format({
                    'predicted_co2': '{:.1f}',
                    'engine_size': '{:.1f}',
                    'fuel_city': '{:.1f}',
                    'fuel_hwy': '{:.1f}'
                }),
                use_container_width=True,
                height=400
            )
            
            # Visualizations
            st.subheader("📈 Visual Analysis")
            
            viz_col1, viz_col2 = st.columns(2)
            
            with viz_col1:
                # Emission distribution
                fig1 = px.histogram(
                    df, x='predicted_co2', nbins=15,
                    title="CO2 Emissions Distribution",
                    labels={'predicted_co2': 'CO2 Emissions (g/km)'},
                    color_discrete_sequence=['#1E88E5']
                )
                st.plotly_chart(fig1, use_container_width=True)
            
            with viz_col2:
                # Emission levels pie chart
                level_counts = df['emission_level'].value_counts().reset_index()
                level_counts.columns = ['Emission Level', 'Count']
                
                fig2 = px.pie(
                    level_counts, names='Emission Level', values='Count',
                    title="Emission Level Distribution",
                    color='Emission Level',
                    color_discrete_map={
                        'High': '#F44336',
                        'Medium': '#FF9800',
                        'Low': '#4CAF50'
                    }
                )
                st.plotly_chart(fig2, use_container_width=True)
            
            # Time series analysis
            if len(df) > 1:
                df['created_at'] = pd.to_datetime(df['created_at'])
                fig3 = px.line(
                    df.sort_values('created_at'), 
                    x='created_at', y='predicted_co2',
                    title="CO2 Emissions Over Time",
                    markers=True
                )
                st.plotly_chart(fig3, use_container_width=True)
            
        except Exception as e:
            st.error(f"Error loading history: {e}")

def show_data_explorer_tab(tab):
    """Display data exploration interface"""
    with tab:
        st.header("📈 Data Explorer")
        
        # File upload section
        st.subheader("📁 Upload Your Data")
        uploaded_file = st.file_uploader(
            "Choose a CSV file", type=['csv'],
            help="Upload your own vehicle data for analysis"
        )
        
        if uploaded_file:
            try:
                df = pd.read_csv(uploaded_file)
                st.success(f"✅ File uploaded successfully! {len(df)} records loaded.")
                
                # Display basic info
                with st.expander("📊 Dataset Overview", expanded=True):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Dataset Shape:**", df.shape)
                        st.write("**Columns:**", list(df.columns))
                    with col2:
                        st.write("**Missing Values:**")
                        st.write(df.isnull().sum())
                
                # Statistical summary
                st.subheader("📈 Statistical Summary")
                st.dataframe(df.describe(), use_container_width=True)
                
                # Visualizations
                st.subheader("📊 Data Visualizations")
                
                if len(df.select_dtypes(include=[np.number]).columns) > 0:
                    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
                    
                    viz_type = st.selectbox(
                        "Select Visualization Type",
                        ["Histogram", "Scatter Plot", "Correlation Matrix", "Box Plot"]
                    )
                    
                    if viz_type == "Histogram":
                        col = st.selectbox("Select Column", numeric_cols)
                        fig = px.histogram(df, x=col, nbins=20, title=f"Distribution of {col}")
                        st.plotly_chart(fig, use_container_width=True)
                    
                    elif viz_type == "Scatter Plot":
                        if len(numeric_cols) >= 2:
                            col1, col2 = st.columns(2)
                            with col1:
                                x_col = st.selectbox("X-axis", numeric_cols)
                            with col2:
                                y_col = st.selectbox("Y-axis", numeric_cols, index=1)
                            
                            fig = px.scatter(df, x=x_col, y=y_col, title=f"{x_col} vs {y_col}")
                            st.plotly_chart(fig, use_container_width=True)
                    
                    elif viz_type == "Correlation Matrix":
                        corr_matrix = df[numeric_cols].corr()
                        fig = px.imshow(
                            corr_matrix, text_auto=True, aspect="auto",
                            color_continuous_scale='RdBu',
                            title="Correlation Matrix"
                        )
                        st.plotly_chart(fig, use_container_width=True)
                    
                    elif viz_type == "Box Plot":
                        col = st.selectbox("Select Column", numeric_cols)
                        fig = px.box(df, y=col, title=f"Box Plot of {col}")
                        st.plotly_chart(fig, use_container_width=True)
                
            except Exception as e:
                st.error(f"Error processing file: {e}")
        
        else:
            # Load default dataset
            df = load_data()
            if not df.empty:
                st.info("📊 Showing default dataset")
                
                with st.expander("📊 Dataset Overview", expanded=True):
                    st.dataframe(df.describe(), use_container_width=True)
                
                # Default visualizations
                viz_option = st.selectbox(
                    "Choose Visualization",
                    ["CO2 Emissions Distribution", "Feature vs CO2 Emissions", "Feature Correlation"]
                )
                
                if viz_option == "CO2 Emissions Distribution":
                    fig = px.histogram(
                        df, x='CO2EMISSIONS', nbins=20,
                        title="Distribution of CO2 Emissions",
                        labels={'CO2EMISSIONS': 'CO2 Emissions (g/km)'}
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                elif viz_option == "Feature vs CO2 Emissions":
                    feature = st.selectbox(
                        "Select Feature",
                        ['ENGINESIZE', 'CYLINDERS', 'FUELCONSUMPTION_CITY', 'FUELCONSUMPTION_HWY']
                    )
                    fig = px.scatter(
                        df, x=feature, y='CO2EMISSIONS',
                        title=f"{feature} vs CO2 Emissions",
                        trendline="lowess"
                    )
                    st.plotly_chart(fig, use_container_width=True)
                
                elif viz_option == "Feature Correlation":
                    numeric_cols = df.select_dtypes(include=np.number).columns
                    corr_matrix = df[numeric_cols].corr()
                    fig = px.imshow(
                        corr_matrix, text_auto=True, aspect="auto",
                        color_continuous_scale='RdBu',
                        title="Feature Correlation Matrix"
                    )
                    st.plotly_chart(fig, use_container_width=True)

def show_reports_tab(tab):
    """Display reports generation interface"""
    with tab:
        st.header("📋 Reports Generation")
        
        report_type = st.selectbox(
            "Select Report Type",
            ["Personal Emission Summary", "Comparative Analysis", "Trend Analysis", "Policy Impact Report"]
        )
        
        if st.button("Generate Report", type="primary"):
            with st.spinner("Generating report..."):
                try:
                    conn = sqlite3.connect(DB_PATH)
                    
                    if report_type == "Personal Emission Summary":
                        # Personal summary report
                        df = pd.read_sql_query('''
                            SELECT * FROM predictions 
                            WHERE user_id = ? 
                            ORDER BY created_at DESC
                        ''', conn, params=(st.session_state.user['id'],))
                        
                        if not df.empty:
                            st.subheader("📊 Personal Emission Summary Report")
                            
                            # Summary statistics
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric("Total Predictions", len(df))
                            with col2:
                                st.metric("Average CO2", f"{df['predicted_co2'].mean():.1f} g/km")
                            with col3:
                                improvement = df['predicted_co2'].iloc[-1] - df['predicted_co2'].iloc[0] if len(df) > 1 else 0
                                st.metric("Improvement", f"{improvement:.1f} g/km", delta=f"{-improvement:.1f}")
                            
                            # Charts
                            fig1 = px.line(df, x='created_at', y='predicted_co2', 
                                         title="Your CO2 Emissions Trend")
                            st.plotly_chart(fig1, use_container_width=True)
                            
                            # Recommendations
                            st.subheader("🎯 Personalized Recommendations")
                            avg_co2 = df['predicted_co2'].mean()
                            if avg_co2 > 200:
                                st.warning("Your average emissions are high. Consider smaller engine vehicles.")
                            elif avg_co2 > 150:
                                st.info("Your emissions are moderate. Look for hybrid options.")
                            else:
                                st.success("Great job! Your emissions are low.")
                    
                    elif report_type == "Comparative Analysis":
                        # Compare with other users (anonymized)
                        user_df = pd.read_sql_query('''
                            SELECT AVG(predicted_co2) as user_avg FROM predictions 
                            WHERE user_id = ?
                        ''', conn, params=(st.session_state.user['id'],))
                        
                        global_df = pd.read_sql_query('''
                            SELECT AVG(predicted_co2) as global_avg FROM predictions
                        ''', conn)
                        
                        if not user_df.empty and not global_df.empty:
                            user_avg = user_df['user_avg'].iloc[0]
                            global_avg = global_df['global_avg'].iloc[0]
                            
                            st.subheader("📊 Comparative Analysis Report")
                            
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Your Average", f"{user_avg:.1f} g/km")
                            with col2:
                                st.metric("Global Average", f"{global_avg:.1f} g/km", 
                                        delta=f"{user_avg - global_avg:.1f}")
                            
                            # Comparison chart
                            comparison_data = pd.DataFrame({
                                'Category': ['Your Average', 'Global Average'],
                                'CO2 Emissions': [user_avg, global_avg]
                            })
                            
                            fig = px.bar(comparison_data, x='Category', y='CO2 Emissions',
                                       title="Your Performance vs Global Average",
                                       color='Category')
                            st.plotly_chart(fig, use_container_width=True)
                    
                    conn.close()
                    
                    # Save report
                    report_data = {
                        'type': report_type,
                        'generated_at': datetime.now().isoformat(),
                        'user_id': st.session_state.user['id']
                    }
                    
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO reports (user_id, report_type, report_data)
                        VALUES (?, ?, ?)
                    ''', (st.session_state.user['id'], report_type, json.dumps(report_data)))
                    conn.commit()
                    conn.close()
                    
                    st.success("✅ Report generated and saved successfully!")
                    
                except Exception as e:
                    st.error(f"Error generating report: {e}")

def show_user_management_tab(tab):
    """Display user management interface (Admin only)"""
    with tab:
        st.header("👥 User Management")
        
        if st.session_state.user['role'] != 'admin':
            st.error("🚫 Access denied. Admin privileges required.")
            return
        
        # User statistics
        df_users = get_all_users()
        
        if not df_users.empty:
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                total_users = len(df_users)
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>Total Users</h4>
                    <h2>{total_users}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col2:
                active_users = len(df_users[df_users['is_active'] == 1])
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>Active Users</h4>
                    <h2>{active_users}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col3:
                admin_users = len(df_users[df_users['role'] == 'admin'])
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>Admin Users</h4>
                    <h2>{admin_users}</h2>
                </div>
                """, unsafe_allow_html=True)
            
            with col4:
                recent_users = len(df_users[pd.to_datetime(df_users['created_at']) > datetime.now() - timedelta(days=7)])
                st.markdown(f"""
                <div class='metric-card'>
                    <h4>New This Week</h4>
                    <h2>{recent_users}</h2>
                </div>
                """, unsafe_allow_html=True)
        
        # User management actions
        st.subheader("👤 Create New User")
        with st.form("create_user_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                new_username = st.text_input("Username")
                new_name = st.text_input("Full Name")
                new_email = st.text_input("Email")
            
            with col2:
                new_whatsapp = st.text_input("WhatsApp")
                new_reg_number = st.text_input("Registration Number")
                new_role = st.selectbox("Role", ["normal", "medium", "admin"])
            
            new_password = st.text_input("Password", type="password")
            
            if st.form_submit_button("Create User"):
                if all([new_username, new_name, new_email, new_password]):
                    success, message = create_user(
                        new_username, new_name, new_email, new_whatsapp,
                        new_reg_number, new_password, new_role
                    )
                    if success:
                        st.success(message)
                        st.rerun()
                    else:
                        st.error(message)
                else:
                    st.error("Please fill in all required fields")
        
        # Users table
        st.subheader("📋 All Users")
        if not df_users.empty:
            # Add action buttons
            for idx, user in df_users.iterrows():
                with st.expander(f"👤 {user['name']} ({user['username']})"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Email:** {user['email']}")
                        st.write(f"**WhatsApp:** {user['whatsapp'] or 'N/A'}")
                        st.write(f"**Registration:** {user['registration_number'] or 'N/A'}")
                    
                    with col2:
                        st.write(f"**Role:** {user['role']}")
                        st.write(f"**Status:** {'Active' if user['is_active'] else 'Inactive'}")
                        st.write(f"**Created:** {user['created_at']}")
                    
                    with col3:
                        if user['username'] != ADMIN_USERNAME:  # Protect main admin
                            # Toggle status
                            new_status = not user['is_active']
                            status_text = "Activate" if not user['is_active'] else "Deactivate"
                            
                            if st.button(f"{status_text}", key=f"status_{user['id']}"):
                                if update_user_status(user['id'], new_status):
                                    st.success(f"User {status_text.lower()}d successfully")
                                    st.rerun()
                            
                            # Delete user
                            if st.button("🗑️ Delete", key=f"delete_{user['id']}", type="secondary"):
                                if delete_user(user['id']):
                                    st.success("User deleted successfully")
                                    st.rerun()
        else:
            st.info("No users found")

def show_analytics_tab(tab):
    """Display system analytics (Admin only)"""
    with tab:
        st.header("📊 System Analytics")
        
        if st.session_state.user['role'] != 'admin':
            st.error("🚫 Access denied. Admin privileges required.")
            return
        
        try:
            conn = sqlite3.connect(DB_PATH)
            
            # Overall statistics
            st.subheader("📈 Overall Statistics")
            
            # Get counts
            total_predictions = pd.read_sql_query("SELECT COUNT(*) as count FROM predictions", conn).iloc[0]['count']
            total_users = pd.read_sql_query("SELECT COUNT(*) as count FROM users", conn).iloc[0]['count']
            total_reports = pd.read_sql_query("SELECT COUNT(*) as count FROM reports", conn).iloc[0]['count']
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Predictions", total_predictions)
            with col2:
                st.metric("Total Users", total_users)
            with col3:
                st.metric("Total Reports", total_reports)
            
            # User activity over time
            st.subheader("👥 User Registration Trends")
            user_trends = pd.read_sql_query('''
                SELECT DATE(created_at) as date, COUNT(*) as registrations
                FROM users 
                GROUP BY DATE(created_at)
                ORDER BY date
            ''', conn)
            
            if not user_trends.empty:
                fig1 = px.line(user_trends, x='date', y='registrations',
                             title="Daily User Registrations")
                st.plotly_chart(fig1, use_container_width=True)
            
            # Prediction activity
            st.subheader("🔮 Prediction Activity")
            prediction_trends = pd.read_sql_query('''
                SELECT DATE(created_at) as date, COUNT(*) as predictions
                FROM predictions 
                GROUP BY DATE(created_at)
                ORDER BY date
            ''', conn)
            
            if not prediction_trends.empty:
                fig2 = px.bar(prediction_trends, x='date', y='predictions',
                            title="Daily Prediction Activity")
                st.plotly_chart(fig2, use_container_width=True)
            
            # Emission levels distribution
            st.subheader("📊 Emission Levels Distribution")
            emission_dist = pd.read_sql_query('''
                SELECT emission_level, COUNT(*) as count
                FROM predictions
                GROUP BY emission_level
            ''', conn)
            
            if not emission_dist.empty:
                fig3 = px.pie(emission_dist, names='emission_level', values='count',
                            title="Distribution of Emission Levels",
                            color='emission_level',
                            color_discrete_map={
                                'High': '#F44336',
                                'Medium': '#FF9800',
                                'Low': '#4CAF50'
                            })
                st.plotly_chart(fig3, use_container_width=True)
            
            # User role distribution
            st.subheader("👤 User Role Distribution")
            role_dist = pd.read_sql_query('''
                SELECT role, COUNT(*) as count
                FROM users
                GROUP BY role
            ''', conn)
            
            if not role_dist.empty:
                fig4 = px.bar(role_dist, x='role', y='count',
                            title="User Role Distribution",
                            color='role')
                st.plotly_chart(fig4, use_container_width=True)
            
            # Visitor trends
            st.subheader("📈 Visitor Trends")
            visitor_trends = pd.read_sql_query('''
                SELECT visit_date, count
                FROM visitor_counter
                ORDER BY visit_date DESC
                LIMIT 30
            ''', conn)
            
            if not visitor_trends.empty:
                fig5 = px.line(visitor_trends, x='visit_date', y='count',
                             title="Daily Visitor Count (Last 30 Days)")
                st.plotly_chart(fig5, use_container_width=True)
            
            conn.close()
            
        except Exception as e:
            st.error(f"Error loading analytics: {e}")
# --- Footer ---
    st.markdown("""
       <hr style="margin-top: 50px;">
       <div style="text-align: center; font-size: 14px; color: gray;">
        &copy; 2025. System Admin: <strong>Abel Mbogo</strong> | WhatsApp: <a href="https://wa.me/255658490848" target="_blank">0658490848</a>
       </div> 
    """, unsafe_allow_html=True)
# --- Run Application ---
if __name__ == "__main__":
    main()