# app.py
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from flask_cors import CORS
import bcrypt
import os
from ibmcloudant.cloudant_v1 import CloudantV1
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from datetime import datetime
import time
import logging
from dotenv import load_dotenv

# ---------------------------------------
# Load Environment Variables
# ---------------------------------------
load_dotenv()

# ---------------------------------------
# Flask App Setup
# ---------------------------------------
app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.environ.get("SECRET_KEY", "fallback-secret-key")
app.config["PERMANENT_SESSION_LIFETIME"] = 3600  # 1 hr

# Enable CORS
CORS(app, supports_credentials=True)

# ---------------------------------------
# Logging Setup
# ---------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------------------------------------
# Cloudant Client Init
# ---------------------------------------
client = None

def get_db_client():
    global client
    if client:
        return client
    
    api_key = os.getenv("CLOUDANT_APIKEY")
    url = os.getenv("CLOUDANT_URL")

    if not api_key or not url:
        logging.error("❌ Missing Cloudant credentials in .env")
        return None

    for attempt in range(3):
        try:
            authenticator = IAMAuthenticator(api_key)
            client = CloudantV1(authenticator=authenticator)
            client.set_service_url(url)

            client.get_server_information().get_result()  # TEST
            logging.info("✅ Connected to IBM Cloudant")
            return client
        except Exception as e:
            logging.error(f"❌ Cloudant connection error (Attempt {attempt+1}): {e}")
            time.sleep(2)

    return None

db = get_db_client()

# ---------------------------------------
# ROUTES — FRONTEND HTML PAGES
# ---------------------------------------

@app.route("/")
def home_page():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/signup")
def signup_page():
    return render_template("new.html")

@app.route("/dashboard/buyer")
def buyer_dashboard():
    # Check if user is logged in
    if "user" not in session:
        return redirect(url_for('login_page'))
    
    # Get user data from session
    user_data = session["user"]
    
    # Debug: Print user data to console
    print(f"🔄 Rendering dashboard for: {user_data}")
    
    return render_template("buydashboard.html", 
                         user_name=user_data.get("name", "User"),
                         user_email=user_data.get("email", ""),
                         user_role=user_data.get("role", "buyer"))

@app.route("/dashboard/seller")
def seller_dashboard():
    return render_template("sellerdashboard.html")

@app.route("/profile/buyer")
def buyer_profile():
    return render_template("profilebuyer.html")

# ---------------------------------------
# API — SIGNUP (FIXED PASSWORD SAVING)
# ---------------------------------------
@app.route("/api/signup", methods=["POST"])
def api_signup():
    try:
        data = request.json
        logging.info(f"📨 Signup request received: {data}")

        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        # Get fields - handle both field names
        name = data.get("name") or data.get("username")
        email = data.get("email") or data.get("username")
        password = data.get("password")
        role = data.get("role")

        logging.info(f"🔍 Extracted fields - name: {name}, email: {email}, role: {role}, password: {'*' * len(password) if password else 'MISSING'}")

        if not all([name, email, password, role]):
            missing = []
            if not name: missing.append("name")
            if not email: missing.append("email")
            if not password: missing.append("password")
            if not role: missing.append("role")
            logging.error(f"❌ Missing required fields: {missing}")
            return jsonify({"success": False, "error": f"Missing fields: {', '.join(missing)}"}), 400

        # Check if email exists
        logging.info(f"🔎 Checking if email exists: {email}")
        try:
            user = db.get_document(db="users", doc_id=email).get_result()
            logging.error(f"❌ Email already exists: {email}")
            return jsonify({"success": False, "error": "Email already registered"}), 409
        except Exception as e:
            if "not found" in str(e).lower() or "404" in str(e):
                logging.info(f"✅ Email available: {email}")
            else:
                logging.error(f"❌ Error checking email: {e}")
                return jsonify({"success": False, "error": "Error checking email availability"}), 500

        # Create user document - FIXED PASSWORD HANDLING
        logging.info("🔐 Hashing password...")
        try:
            # FIX: Use proper bcrypt hashing
            hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            # Convert bytes to string for JSON storage
            hashed_pw_str = hashed_pw.decode('utf-8')
            logging.info(f"✅ Password hashed successfully. Hash: {hashed_pw_str[:20]}...")
        except Exception as e:
            logging.error(f"❌ Password hashing failed: {e}")
            return jsonify({"success": False, "error": "Password processing failed"}), 500

        user_doc = {
            "_id": email,
            "name": name,
            "email": email,
            "password": hashed_pw_str,  # ✅ Now storing actual hash
            "role": role,
            "created_at": datetime.utcnow().isoformat()
        }

        logging.info(f"📝 User document to save: {user_doc}")

        # Save to database
        try:
            result = db.put_document(
                db="users", 
                doc_id=email,
                document=user_doc
            ).get_result()
            logging.info(f"✅ User document created successfully: {result}")
            
            return jsonify({
                "success": True, 
                "message": "Signup successful",
                "user_id": email
            }), 201

        except Exception as e:
            logging.error(f"❌ Database creation failed: {e}")
            return jsonify({"success": False, "error": f"Database error: {str(e)}"}), 500

    except Exception as e:
        logging.error(f"❌ Unexpected error in signup: {e}")
        return jsonify({"success": False, "error": "Unexpected server error"}), 500
# ---------------------------------------
# API — LOGIN (WITH DEBUGGING)
# ---------------------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    try:
        data = request.json
        logging.info(f"📨 Login request received: {data}")

        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        email = data.get("email")
        password = data.get("password")

        logging.info(f"🔍 Login attempt for email: {email}")

        if not email or not password:
            return jsonify({"success": False, "error": "Email and password required"}), 400

        # Try to find the user
        logging.info(f"🔎 Looking up user in database: {email}")
        try:
            user = db.get_document(db="users", doc_id=email).get_result()
            logging.info(f"✅ User found: {user}")
        except Exception as e:
            logging.error(f"❌ User not found or error: {e}")
            return jsonify({"success": False, "error": "Invalid email or password"}), 401

        # Check if we have the password field
        if "password" not in user:
            logging.error(f"❌ No password field in user document: {user.keys()}")
            return jsonify({"success": False, "error": "User data corrupted"}), 500

        # Debug the password comparison
        logging.info(f"🔐 Comparing passwords...")
        logging.info(f"   Input password: {password}")
        logging.info(f"   Stored hash: {user['password']}")
        
        try:
            # Check if the password matches
            password_matches = bcrypt.checkpw(password.encode(), user["password"].encode())
            logging.info(f"   Password matches: {password_matches}")
            
            if not password_matches:
                logging.error("❌ Password does not match")
                return jsonify({"success": False, "error": "Invalid email or password"}), 401
                
        except Exception as e:
            logging.error(f"❌ Password comparison error: {e}")
            return jsonify({"success": False, "error": "Authentication error"}), 500

        # Login successful
        logging.info(f"✅ Login successful for: {email}")

        # Store session
        session["user"] = {
            "email": user["email"],
            "role": user["role"],
            "name": user.get("name", "")
        }

        # Determine redirect
        redirect_url = "/dashboard/buyer" if user["role"] == "buyer" else "/dashboard/seller"
        logging.info(f"🔄 Redirecting to: {redirect_url}")

        return jsonify({
            "success": True, 
            "message": "Login successful", 
            "user": {
                "email": user["email"],
                "role": user["role"],
                "name": user.get("name", "")
            },
            "redirect": redirect_url
        })

    except Exception as e:
        logging.error(f"❌ Unexpected error in login: {e}")
        return jsonify({"success": False, "error": "Login failed"}), 500

# ... your existing routes ...

# ---------------------------------------
# DEBUG — Database Status
# ---------------------------------------
@app.route("/api/debug/db-status")
def debug_db_status():
    try:
        # Check if we can list databases
        dbs = db.get_all_dbs().get_result()
        logging.info(f"📊 Available databases: {dbs}")
        
        # Check if users database exists and can be accessed
        try:
            db_info = db.get_database_information(db="users").get_result()
            users_db_info = f"Users DB exists: {db_info}"
        except Exception as e:
            users_db_info = f"Users DB error: {e}"
            
        return jsonify({
            "db_connected": True,
            "available_databases": dbs,
            "users_db_status": users_db_info
        })
    except Exception as e:
        return jsonify({
            "db_connected": False,
            "error": str(e)
        })

# ---------------------------------------
# Ensure Users Database Exists
# ---------------------------------------
def ensure_users_database():
    try:
        # Try to get database info - if it fails, database doesn't exist
        db.get_database_information(db="users").get_result()
        logging.info("✅ Users database exists")
    except Exception as e:
        try:
            # Create the database
            db.put_database(db="users").get_result()
            logging.info("✅ Created users database")
        except Exception as create_error:
            logging.error(f"❌ Failed to create users database: {create_error}")

# Call this after initializing db
if db:
    ensure_users_database()

# ---------------------------------------
# DEBUG — List All Users
# ---------------------------------------
@app.route("/api/debug/users")
def debug_users():
    try:
        # Get all users
        result = db.post_all_docs(db="users", include_docs=True).get_result()
        users = []
        for row in result.get('rows', []):
            user = row.get('doc', {})
            # Don't show password in the response
            if 'password' in user:
                user['password'] = '***HIDDEN***'
            users.append(user)
        
        return jsonify({
            "total_users": len(users),
            "users": users
        })
    except Exception as e:
        return jsonify({"error": str(e)})
    
    # ---------------------------------------
# DEBUG — Check Specific User
# ---------------------------------------
@app.route("/api/debug/user/<email>")
def debug_user(email):
    try:
        user = db.get_document(db="users", doc_id=email).get_result()
        return jsonify({
            "user_exists": True,
            "user_data": user
        })
    except Exception as e:
        return jsonify({
            "user_exists": False,
            "error": str(e)
        })
    
    # ---------------------------------------
# DEBUG — Reset User Password
# ---------------------------------------
@app.route("/api/debug/reset-password/<email>", methods=["POST"])
def debug_reset_password(email):
    try:
        data = request.json
        new_password = data.get("password")
        
        if not new_password:
            return jsonify({"success": False, "error": "Password required"}), 400

        # Hash the new password
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Get the existing user
        user = db.get_document(db="users", doc_id=email).get_result()
        
        # Update the password
        user["password"] = hashed_pw
        
        # Save back to database
        db.put_document(db="users", doc_id=email, document=user)
        
        return jsonify({
            "success": True, 
            "message": f"Password reset for {email}",
            "new_hash": hashed_pw[:20] + "..."
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    

    # ---------------------------------------
# DASHBOARD DATA APIs
# ---------------------------------------

@app.route("/api/user-data")
def get_user_data():
    if "user" not in session:
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    return jsonify({
        "success": True,
        "user": session["user"]
    })

@app.route("/api/user-metrics")
def get_user_metrics():
    if "user" not in session:
        return jsonify({"success": False, "error": "Not authenticated"}), 401
    
    user_email = session["user"]["email"]
    
    try:
        # Get user's purchase history for metrics
        result = db.post_all_docs(
            db="purchases",
            include_docs=True,
            start_key=f"{user_email}_",
            end_key=f"{user_email}_\ufff0"
        ).get_result()
        
        purchases = []
        for row in result.get('rows', []):
            purchase = row.get('doc', {})
            purchases.append(purchase)
        
        # Calculate metrics
        total_orders = len(purchases)
        pending_deliveries = len([p for p in purchases if p.get('status') in ['shipped', 'pending']])
        total_spent = sum(p.get('total_amount', 0) for p in purchases)
        wishlist_items = 0  # You can add wishlist functionality later
        
        return jsonify({
            "success": True,
            "metrics": {
                "total_orders": total_orders,
                "pending_deliveries": pending_deliveries,
                "wishlist_items": wishlist_items,
                "total_spent": total_spent
            }
        })
        
    except Exception as e:
        logging.error(f"Error fetching user metrics: {e}")
        return jsonify({
            "success": True,
            "metrics": {
                "total_orders": 0,
                "pending_deliveries": 0,
                "wishlist_items": 0,
                "total_spent": 0
            }
        })
    
@app.route("/api/debug/session")
def debug_session():
    return jsonify({
        "session_data": dict(session),
        "user_in_session": "user" in session
    })    

# ---------------------------------------
# Run Server
# ---------------------------------------
if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "true").lower() == "true"

    logging.info("🚀 Starting Flask Server...")
    logging.info(f"Database Connected: {db is not None}")
    logging.info(f"Secret Key Loaded: {bool(app.secret_key)}")

    app.run(host="0.0.0.0", port=port, debug=debug)