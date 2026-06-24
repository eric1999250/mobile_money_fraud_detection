"""
app.py — Flask REST API Server
================================
Routes:
  Pages
    GET  /                        → index.html
    GET  /login                   → login.html
    GET  /dashboard               → dashboard.html

  Auth
    POST /api/register            → create account (+ face at signup)
    POST /api/login               → login, get session token
    POST /api/validate-session    → check token, return user info
    POST /api/logout              → destroy session
    POST /api/reset-password      → request reset token
    POST /api/reset-password/confirm → apply new password with token
    POST /api/update-face         → store/update face encoding

  PIN
    POST /api/verify-pin          → check PIN, track failures, block after 3
    POST /api/set-pin             → set PIN for first time (or after reset)
    POST /api/reset-pin           → reset PIN via National ID + face scan

  Transfers
    POST /api/transfer            → initiate transfer (fraud-gated)
    POST /api/calculate-fee       → fee preview before transfer
    GET  /api/transfer-history    → paginated transfer history
    POST /api/check-recipient     → lookup recipient name

  Travel
    POST /api/travel/register     → mark user as abroad (blocks transfers)
    POST /api/travel/reactivate   → re-enable after return
    GET  /api/travel/status/<phone> → check travel record

  Admin / Dashboard
    GET  /api/dashboard/stats     → system-wide statistics
    GET  /api/fraud/alerts        → unacknowledged fraud alerts
    POST /api/fraud/alerts/acknowledge → mark alert as seen
    POST /api/pin/attempt         → log PIN attempt
    GET  /api/pin/status/<phone>  → PIN security score
    GET  /api/admin/all-users     → list all users
    POST /api/admin/user-lookup   → look up user by phone

  System
    GET  /api/health              → health check
"""

import psycopg2
import psycopg2.extras
import os
import base64
import hashlib
import uuid as uuid_lib
from datetime import datetime
import time

from flask import Flask, request, jsonify
from flask_cors import CORS

from auth_system import AuthenticationSystem
from money_transfer import MoneyTransferSystem
from fraud_detection import (
    RealTimeFraudDetector,
    TravelMonitoringSystem,
    PinMonitoringSystem,
    UserRegistrationSystem,
)

# ─────────────────────────────────────────────────────────────────────────────
# APP SETUP
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024   # 16 MB

# PostgreSQL Configuration
DB_CONFIG = {
    'dbname': 'momo_fraud',
    'user': 'postgres',
    'password': 'Eric@!99',
    'host': 'localhost',
    'port': '5432'
}

def get_db_connection():
    """Create and return a PostgreSQL database connection."""
    return psycopg2.connect(**DB_CONFIG)

auth_system     = AuthenticationSystem(DB_CONFIG)
transfer_system = MoneyTransferSystem(DB_CONFIG)
fraud_detector  = RealTimeFraudDetector(DB_CONFIG)
user_reg        = UserRegistrationSystem(DB_CONFIG)
travel_system   = TravelMonitoringSystem(user_reg)
pin_monitor     = PinMonitoringSystem(user_reg)

auth_system.cleanup_expired_sessions()

provider_sessions = {}


def _ensure_access_logs_table():
    """Create access_logs table if it doesn't exist."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id          SERIAL PRIMARY KEY,
            event_type  TEXT NOT NULL,
            identifier  TEXT,
            full_name   TEXT,
            role        TEXT,
            ip_address  TEXT,
            status      TEXT NOT NULL,
            detail      TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    cur.close()
    conn.close()

_ensure_access_logs_table()


def _log_access(event_type: str, identifier: str, full_name: str,
                role: str, status: str, detail: str = ""):
    """Write one row to access_logs."""
    try:
        ip = request.remote_addr or "unknown"
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO access_logs
               (event_type, identifier, full_name, role, ip_address, status, detail)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (event_type, identifier, full_name, role, ip, status, detail)
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass  # never break the main flow


def _session_token() -> str | None:
    hdr = request.headers.get("Authorization", "")
    if hdr.startswith("Bearer "):
        return hdr[7:]
    return None


def _ok(data: dict, code: int = 200):
    if "success" not in data:
        data = {"success": True, **data}
    return jsonify(data), code


def _err(msg: str, code: int = 400):
    return jsonify({"success": False, "error": msg}), code


def _hash_pin(pin: str) -> str:
    """SHA-256 hash of PIN."""
    return hashlib.sha256(pin.encode()).hexdigest()


def _table_exists(conn, table: str) -> bool:
    c = conn.cursor()
    c.execute("SELECT to_regclass(%s)", (table,))
    return c.fetchone()[0] is not None


def _ensure_pin_columns():
    """Ensure PIN columns exist (migration-safe)."""
    conn = psycopg2.connect(**DB_CONFIG)
    c = conn.cursor()
    for col, typedef in [
        ("pin_hash",       "TEXT"),
        ("pin_salt",       "TEXT"),
        ("pin_attempts",   "INTEGER DEFAULT 0"),
        ("pin_blocked",    "BOOLEAN DEFAULT FALSE"),
        ("pin_fail_count", "INTEGER DEFAULT 0"),
        ("insuf_count",    "INTEGER DEFAULT 0"),
    ]:
        try:
            c.execute(f"ALTER TABLE users ADD COLUMN IF NOT EXISTS {col} {typedef}")
        except Exception:
            pass
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────────────────────────────────────
# PAGE ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return _ok({"message": "MoMo Shield API v2.0 — use /api/* endpoints"})


# ─────────────────────────────────────────────────────────────────────────────
# AUTH ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/register", methods=["POST"])
def register():
    print("[REGISTER] Request received", flush=True)
    try:
        data        = request.get_json() or {}
        print(f"[REGISTER] Data keys: {list(data.keys())}", flush=True)
        full_name   = data.get("fullName", "").strip()
        phone       = data.get("phone", "").strip()
        email       = data.get("email", "").strip()
        national_id = data.get("nationalId", "").strip()
        password    = data.get("password", "")
        face_b64    = data.get("face_base64")
        pin         = data.get("pin", "").strip()

        for field, val in [("fullName", full_name), ("phone", phone),
                           ("email", email), ("nationalId", national_id),
                           ("password", password)]:
            if not val:
                return _err(f"Missing required field: {field}")

        # Face is required at registration
        if not face_b64:
            return _err("Face scan is required during registration.")

        result = auth_system.create_account(
            phone, full_name, national_id, email, password, face_b64)
        
        # Add face validation info to response for debugging
        if result.get("success") and result.get("face_image_path"):
            result["debug_info"] = {
                "face_saved_to": result.get("face_image_path"),
                "face_size": result.get("face_size", "unknown"),
                "message": "Face image saved to uploads folder for verification"
            }

        if result["success"] and pin and len(pin) >= 4:
            conn = psycopg2.connect(**DB_CONFIG)
            cr = conn.cursor()
            cr.execute(
                "UPDATE users SET pin_hash=%s, pin_blocked=FALSE, pin_fail_count=0 WHERE phone_number=%s",
                (_hash_pin(pin), phone)
            )
            conn.commit()
            conn.close()

        return _ok(result) if result["success"] else _err(result["error"])

    except Exception as e:
        import traceback
        traceback.print_exc()
        return _err(f"Registration failed: {e}", 500)


@app.route("/api/validate-face", methods=["POST"])
def validate_face():
    """
    Validate face quality ONLY — detect + check landmarks.
    Never saves to disk or DB. Used by Reset PIN and fraud face gate.
    """
    try:
        data = request.get_json() or {}
        face_b64 = data.get("face_base64")

        if not face_b64:
            return _err("No face image provided")

        result = user_reg.validate_face_quality_only(face_b64)

        if result["error"]:
            return _err(result["error"])

        return _ok({
            "face_detected": True,
            "face_count": result.get("face_count", 1),
            "face_size": result.get("face_size", "unknown"),
            "message": "Face detected and validated"
        })

    except Exception as e:
        return _err(f"Face validation failed: {e}", 500)


@app.route("/api/login", methods=["POST"])
def login():
    try:
        data     = request.get_json() or {}
        email    = data.get("email", "").strip()
        password = data.get("password", "")

        hashed = hashlib.sha256(password.encode()).hexdigest()
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute("SELECT id, name, email FROM service_providers WHERE email=%s AND password=%s AND is_active=TRUE", (email, hashed))
        provider = c.fetchone()
        conn.close()

        if provider:
            import uuid
            token = str(uuid.uuid4())
            provider_sessions[token] = {
                "id": provider[0], "name": provider[1],
                "email": provider[2], "role": "provider"
            }
            _log_access("LOGIN", provider[2], provider[1], "provider", "SUCCESS")
            return _ok({
                "success": True,
                "session_token": token,
                "user": {"name": provider[1], "email": provider[2]},
                "dashboard_type": "provider",
                "dashboard_url": "/provider_dashboard"
            })

        result = auth_system.authenticate_user(password=password, email=email or None)
        if result["success"]:
            user_email = result.get("user", {}).get("email", "")
            user_name  = result.get("user", {}).get("name", "")
            role = result.get("user", {}).get("role", "user")
            if role == "admin":
                result["dashboard_type"] = "admin"
                result["dashboard_url"] = "/admin_dashboard"
            elif role == "provider":
                result["dashboard_type"] = "provider"
                result["dashboard_url"] = "/provider_dashboard"
            else:
                role = "user"
                result["dashboard_type"] = "user"
                result["dashboard_url"] = "/user_dashboard"

            _log_access("LOGIN", user_email, user_name, role, "SUCCESS")

            # Tell frontend if user has a PIN set
            phone = result.get("user", {}).get("phone", "")
            if phone:
                conn2 = psycopg2.connect(**DB_CONFIG)
                c2 = conn2.cursor()
                c2.execute("SELECT pin_hash, pin_blocked FROM users WHERE phone_number=%s", (phone,))
                row = c2.fetchone()
                conn2.close()
                result["has_pin"]    = bool(row and row[0])
                result["pin_blocked"] = bool(row and row[1])

        else:
            _log_access("LOGIN", email or "unknown", "", "unknown", "FAILED",
                        result.get("error", "Invalid credentials"))

        return _ok(result) if result["success"] else _err(result["error"], 401)

    except Exception as e:
        return _err(f"Login failed: {e}", 500)


@app.route("/api/validate-session", methods=["POST"])
def validate_session():
    try:
        data  = request.get_json() or {}
        token = data.get("session_token", "")

        if token in provider_sessions:
            provider = provider_sessions[token]
            if provider.get("role") == "provider":
                return _ok({
                    "success": True,
                    "user": {"name": provider["name"], "email": provider["email"]},
                    "dashboard_type": "provider",
                    "dashboard_url": "/provider_dashboard"
                })

        user = auth_system.validate_session(token)
        if user:
            user_email = user.get("email", "")
            is_admin = user_email.endswith("@admin.com")
            is_provider = user_email.endswith("@provider.com")
            
            if is_admin:
                dashboard_type = "admin"
                dashboard_url = "/admin_dashboard"
            elif is_provider:
                dashboard_type = "provider"
                dashboard_url = "/provider_dashboard"
            else:
                dashboard_type = "user"
                dashboard_url = "/user_dashboard"

            # Include PIN status
            phone = user.get("phone", "")
            has_pin = False
            pin_blocked = False
            if phone:
                conn = psycopg2.connect(**DB_CONFIG)
                cv = conn.cursor()
                cv.execute("SELECT pin_hash, pin_blocked FROM users WHERE phone_number=%s", (phone,))
                row = cv.fetchone()
                conn.close()
                has_pin     = bool(row and row[0])
                pin_blocked  = bool(row and row[1])

            return _ok({
                "success": True,
                "user": user,
                "has_pin": has_pin,
                "pin_blocked": pin_blocked,
                "dashboard_type": dashboard_type,
                "dashboard_url": dashboard_url
            })
        return _err("Session expired or invalid.", 401)
    except Exception as e:
        return _err(f"Session validation failed: {e}", 500)


@app.route("/api/logout", methods=["POST"])
def logout():
    try:
        data  = request.get_json() or {}
        token = data.get("session_token", "") or _session_token() or ""
        # Try to find who is logging out for the log entry
        try:
            user = auth_system.validate_session(token)
            if user:
                _log_access("LOGOUT", user.get("email",""), user.get("name",""), "user", "SUCCESS")
            else:
                # Check provider sessions
                prov = provider_sessions.get(token)
                if prov:
                    _log_access("LOGOUT", prov.get("email",""), prov.get("name",""), "provider", "SUCCESS")
        except Exception:
            pass
        return _ok(auth_system.logout(token))
    except Exception as e:
        return _err(f"Logout failed: {e}", 500)


@app.route("/api/reset-password", methods=["POST"])
def request_reset():
    try:
        data  = request.get_json() or {}
        email = data.get("email", "").strip()
        if not email:
            return _err("Email is required.")
        result = auth_system.request_password_reset(email)
        return _ok(result) if result["success"] else _err(result["error"])
    except Exception as e:
        return _err(f"Reset request failed: {e}", 500)


@app.route("/api/reset-password/confirm", methods=["POST"])
def confirm_reset():
    try:
        data     = request.get_json() or {}
        token    = data.get("token", "")
        new_pass = data.get("new_password", "")
        if not token or not new_pass:
            return _err("token and new_password are required.")
        result = auth_system.reset_password(token, new_pass)
        return _ok(result) if result["success"] else _err(result["error"])
    except Exception as e:
        return _err(f"Password reset failed: {e}", 500)


@app.route("/api/update-face", methods=["POST"])
def update_face():
    """
    Update face for an existing user.
    Requires: phone_number + national_id (must match DB) + face_base64.
    The new face must be similar to the existing stored face (distance ≤ 0.6)
    to prevent someone else hijacking the account.
    """
    try:
        data        = request.get_json() or {}
        token       = data.get("session_token", "") or _session_token() or ""
        face_b64    = data.get("face_base64", "")
        phone_in    = data.get("phone_number", "").strip()
        national_id = data.get("national_id", "").strip()

        # ── Session required ──────────────────────────────────────────────
        user = auth_system.validate_session(token)
        if not user:
            return _err("Invalid or expired session.", 401)

        if not face_b64:
            return _err("face_base64 is required.")
        if not phone_in:
            return _err("phone_number is required.")
        if not national_id:
            return _err("national_id is required.")

        # ── Normalise phone ───────────────────────────────────────────────
        validated_phone = auth_system.validate_phone_number(phone_in)
        if not validated_phone:
            return _err("Invalid phone number format.")

        # ── Phone must belong to the session user ─────────────────────────
        if validated_phone != user["phone"]:
            return _err("Phone number does not match your account.")

        # ── Verify national_id matches DB record ──────────────────────────
        conn = psycopg2.connect(**DB_CONFIG)
        cuf = conn.cursor()
        cuf.execute(
            "SELECT national_id, face_encoding, face_image_path FROM users WHERE phone_number=%s",
            (validated_phone,)
        )
        row = cuf.fetchone()
        conn.close()

        if not row:
            return _err("User not found.")

        stored_national_id, stored_face_enc, stored_face_path = row[0], row[1], row[2]

        if str(stored_national_id).strip() != str(national_id).strip():
            return _err("National ID does not match our records.")

        # ── If a face already exists, new face must be similar (same person) ──
        if stored_face_enc:
            similarity_check = user_reg.verify_face_from_base64(validated_phone, face_b64, tolerance=0.60)
            if not similarity_check.get("verified"):
                err_msg = similarity_check.get("error", "")
                if "does not match" in (err_msg or "") or "similar" in (err_msg or "") or not err_msg:
                    _log_access(
                        "FACE_UPDATE_FAIL",
                        user.get("phone", ""),
                        user.get("name", ""),
                        "user",
                        "FAILED",
                        "Face does not match registered face — update rejected"
                    )
                    return _err(
                        " Face verification failed — your face does not match the registered face on this account.\n\n"
                        "Possible reasons:\n"
                        "• You are not the registered owner of this account\n"
                        "• Poor lighting — move to a brighter area and try again\n"
                        "• Remove glasses, hat, or anything covering your face\n"
                        "• Look directly at the camera — avoid angles\n\n"
                        "This attempt has been blocked and logged for security. "
                        "If this is truly your account, contact support with your National ID."
                    )
                _log_access(
                    "FACE_UPDATE_FAIL",
                    user.get("phone", ""),
                    user.get("name", ""),
                    "user",
                    "FAILED",
                    (err_msg or "Face verification failed")[:200]
                )
                return _err(err_msg or "Face verification failed.")

        # ── Run the update — overwrites existing DB encoding + folder image ──
        result = user_reg.update_face_encoding(validated_phone, face_b64, overwrite=True)
        return _ok(result) if result["success"] else _err(result["error"])

    except Exception as e:
        return _err(f"Face update failed: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# PIN ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/set-pin", methods=["POST"])
def set_pin():
    """Set PIN for the first time (called from dashboard after login if no PIN)."""
    try:
        token = _session_token()
        if not token:
            return _err("Missing Authorization header.", 401)

        data = request.get_json() or {}
        pin  = data.get("pin", "").strip()

        if not pin or len(pin) < 4:
            return _err("PIN must be at least 4 digits.")
        if not pin.isdigit():
            return _err("PIN must contain digits only.")

        user = auth_system.validate_session(token)
        if not user:
            return _err("Invalid session.", 401)

        conn = psycopg2.connect(**DB_CONFIG)
        cs = conn.cursor()
        cs.execute(
            "UPDATE users SET pin_hash=%s, pin_blocked=FALSE, pin_fail_count=0 WHERE phone_number=%s",
            (_hash_pin(pin), user["phone"])
        )
        conn.commit()
        conn.close()

        return _ok({"success": True, "message": "PIN set successfully."})
    except Exception as e:
        return _err(f"Set PIN failed: {e}", 500)


@app.route("/api/verify-pin", methods=["POST"])
def verify_pin():
    """
    Verify transaction PIN.
    - Wrong PIN 3 times → pin_blocked = 1
    - Returns: { success, blocked, remaining }
    """
    try:
        token = _session_token()
        if not token:
            return _err("Missing Authorization header.", 401)

        data = request.get_json() or {}
        pin  = data.get("pin", "").strip()

        if not pin:
            return _err("PIN is required.")

        user = auth_system.validate_session(token)
        if not user:
            return _err("Invalid session.", 401)

        conn = psycopg2.connect(**DB_CONFIG)
        cp = conn.cursor()
        cp.execute(
            "SELECT pin_hash, pin_blocked, pin_fail_count FROM users WHERE phone_number=%s",
            (user["phone"],)
        )
        row = cp.fetchone()

        if not row or not row[0]:
            conn.close()
            return _err("No PIN set. Please set your PIN first.")

        pin_hash, pin_blocked, fail_count = row

        # Already blocked
        if pin_blocked:
            conn.close()
            return _ok({"success": False, "blocked": True,
                        "error": "PIN is blocked. Go to Reset PIN to unblock."})

        # Check PIN
        if _hash_pin(pin) == pin_hash:
            # Correct — reset fail count
            cp.execute(
                "UPDATE users SET pin_fail_count=0 WHERE phone_number=%s",
                (user["phone"],)
            )
            conn.commit()
            conn.close()
            return _ok({"success": True, "blocked": False})
        else:
            # Wrong PIN
            fail_count += 1
            if fail_count >= 3:
                cp.execute(
                    "UPDATE users SET pin_fail_count=3, pin_blocked=TRUE WHERE phone_number=%s",
                    (user["phone"],)
                )
                conn.commit()
                conn.close()
                # Raise fraud alert — 3 wrong PIN attempts is suspicious
                try:
                    fraud_detector.alert_system.raise_alert(
                        user["phone"], 0, 0.85, "HIGH", "BLOCK",
                        f"PIN blocked — 3 consecutive incorrect PIN attempts. "
                        f"Possible unauthorized access attempt on account {user['phone']}."
                    )
                except Exception:
                    pass
                return _ok({
                    "success": False, "blocked": True,
                    "error": "PIN blocked after 3 incorrect attempts. Go to Reset PIN to unblock."
                })
            else:
                remaining = 3 - fail_count
                cp.execute(
                    "UPDATE users SET pin_fail_count=%s WHERE phone_number=%s",
                    (fail_count, user["phone"])
                )
                conn.commit()
                conn.close()
                # Alert admin on each wrong PIN attempt
                try:
                    fraud_detector.alert_system.raise_alert(
                        user["phone"], 0, 0.5 + (fail_count * 0.15), "MEDIUM", "REQUIRE_FACE",
                        f"Incorrect PIN — attempt {fail_count} of 3. "
                        f"{remaining} attempt{'s' if remaining != 1 else ''} remaining before account locks."
                    )
                except Exception:
                    pass
                return _ok({
                    "success": False, "blocked": False,
                    "remaining": remaining,
                    "error": f"Incorrect PIN. {remaining} attempt{'s' if remaining != 1 else ''} remaining."
                })

    except Exception as e:
        return _err(f"PIN verification failed: {e}", 500)


@app.route("/api/verify-identity", methods=["POST"])
def verify_identity():
    """
    Step-1 identity gate for Reset PIN and Update Face.
    Accepts phone_number + national_id and confirms they match a DB record.
    Returns { success, name } on match or { error } on mismatch.
    Does NOT require a session token — the user may be locked out.
    """
    try:
        data        = request.get_json() or {}
        phone_in    = data.get("phone_number", "").strip()
        national_id = data.get("national_id", "").strip()

        if not phone_in:
            return _err("Phone number is required.")
        if not national_id:
            return _err("National ID is required.")

        validated_phone = auth_system.validate_phone_number(phone_in)
        if not validated_phone:
            return _err("Invalid phone number format.")

        conn = psycopg2.connect(**DB_CONFIG)
        cvi = conn.cursor()
        cvi.execute(
            "SELECT full_name, national_id FROM users WHERE phone_number=%s",
            (validated_phone,)
        )
        row = cvi.fetchone()
        conn.close()

        if not row:
            return _err("No account found with this phone number.")

        stored_name, stored_nid = row[0], row[1]

        if str(stored_nid).strip() != str(national_id).strip():
            return _err("Phone number and National ID do not match our records.")

        return _ok({"success": True, "name": stored_name})

    except Exception as e:
        return _err(f"Identity verification failed: {e}", 500)


@app.route("/api/reset-pin", methods=["POST"])
def reset_pin():
    """
    Reset PIN using National ID + face scan.
    Steps:
      1. Verify session
      2. Check National ID matches user record
      3. Verify face against stored face encoding
      4. Set new PIN, unblock, reset fail count
    """
    try:
        token = _session_token()
        if not token:
            return _err("Missing Authorization header.", 401)

        data        = request.get_json() or {}
        national_id = data.get("national_id", "").strip()
        new_pin     = data.get("new_pin", "").strip()
        face_b64    = data.get("face_base64", "")

        if not national_id:
            return _err("National ID is required.")
        if not new_pin or len(new_pin) < 4:
            return _err("New PIN must be at least 4 digits.")
        if not new_pin.isdigit():
            return _err("PIN must contain digits only.")
        if not face_b64:
            return _err("Face scan is required.")

        user = auth_system.validate_session(token)
        if not user:
            return _err("Invalid session.", 401)

        # Step 1: Verify National ID matches
        conn = psycopg2.connect(**DB_CONFIG)
        crp = conn.cursor()
        crp.execute(
            "SELECT national_id, face_encoding FROM users WHERE phone_number=%s",
            (user["phone"],)
        )
        row = crp.fetchone()
        conn.close()

        if not row:
            return _err("User not found.")

        stored_national_id, stored_face_encoding = row[0], row[1]

        if str(stored_national_id).strip() != str(national_id).strip():
            return _err("National ID does not match our records.")

        # Step 2: Verify face
        if not stored_face_encoding:
            return _err("No face registered on this account. Contact support.")

        face_match = _verify_face(face_b64, stored_face_encoding)
        if not face_match["match"]:
            _log_access(
                "PIN_RESET_FACE_FAIL",
                user.get("phone", ""),
                user.get("name", ""),
                "user",
                "FAILED",
                face_match["reason"][:200]
            )
            return _err(f"Face verification failed: {face_match['reason']}")

        # Step 3: Set new PIN, unblock
        conn = psycopg2.connect(**DB_CONFIG)
        crp2 = conn.cursor()
        crp2.execute(
            "UPDATE users SET pin_hash=%s, pin_blocked=FALSE, pin_fail_count=0 WHERE phone_number=%s",
            (_hash_pin(new_pin), user["phone"])
        )
        conn.commit()
        conn.close()

        return _ok({"success": True, "message": "PIN reset successfully. You can now use your new PIN."})

    except Exception as e:
        return _err(f"PIN reset failed: {e}", 500)


def _verify_face(face_b64: str, stored_encoding_bytes: bytes) -> dict:
    """
    Validate face quality then compare against the stored encoding.
    Returns { match: bool, reason: str }.
    NEVER falls back to approving a face if face_recognition is unavailable —
    missing library is treated as a hard failure to prevent bypass.
    """
    try:
        import numpy as np

        # ── Step 1: Quality check ONLY — never saves to disk ────────────────
        # validate_face_quality_only runs all the same gates (brightness, size,
        # landmarks, eye openness, head upright) but never writes a file.
        # extract_face_encoding_from_base64 is ONLY used during registration.
        quality = user_reg.validate_face_quality_only(face_b64)
        if quality["error"]:
            return {"match": False, "reason": quality["error"]}

        # ── Step 2: Compare submitted encoding against stored encoding ────────
        try:
            import face_recognition
        except ImportError:
            # face_recognition library is not installed — HARD FAIL.
            # Never auto-approve: that would allow anyone to bypass face checks.
            return {
                "match": False,
                "reason": (
                    "Face verification library is not available on this server. "
                    "Face check cannot be completed — action blocked for security. "
                    "Please contact support to resolve this."
                )
            }

        submitted_encoding = np.frombuffer(quality["encoding"], dtype=np.float64)
        if len(submitted_encoding) != 128:
            submitted_encoding = np.frombuffer(quality["encoding"], dtype=np.float32).astype(np.float64)

        stored_encoding = np.frombuffer(stored_encoding_bytes, dtype=np.float64)
        if len(stored_encoding) != 128:
            stored_encoding = np.frombuffer(stored_encoding_bytes, dtype=np.float32).astype(np.float64)
        if len(stored_encoding) != 128:
            return {"match": False, "reason": "Stored face encoding is corrupted. Contact support."}

        distance = face_recognition.face_distance([stored_encoding], submitted_encoding)[0]
        if distance <= 0.55:
            return {"match": True, "reason": f"Face matched (distance: {distance:.3f})"}
        else:
            return {
                "match": False,
                "reason": (
                    " Face verification failed — this face does not match the account owner.\n\n"
                    "Possible reasons:\n"
                    "• You are not the registered owner of this account\n"
                    "• Poor lighting — move to a brighter area and try again\n"
                    "• Remove glasses, hat, or anything covering your face\n"
                    "• Look directly at the camera — avoid angles\n\n"
                    "This attempt has been blocked and logged for security. "
                    "If this is truly your account, contact support with your National ID."
                )
            }

    except Exception as e:
        return {"match": False, "reason": f"Verification error: {e}"}


# ─────────────────────────────────────────────────────────────────────────────
# TRANSFER ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/transfer", methods=["POST"])
def transfer():
    try:
        token = _session_token()
        if not token:
            return _err("Missing Authorization header.", 401)

        data            = request.get_json() or {}
        recipient_phone = data.get("recipient_phone", "").strip()
        amount_raw      = data.get("amount", 0)
        transfer_type   = data.get("transfer_type", "mobile_money")
        face_b64        = data.get("face_base64")

        try:
            amount = float(amount_raw)
        except (TypeError, ValueError):
            return _err("Invalid amount.")

        # ── Face is MANDATORY for every transaction ───────────────────────
        if not face_b64:
            return _ok({
                "success"      : False,
                "face_required": True,
                "action"       : "REQUIRE_FACE",
                "message"      : "Face verification is required for every transaction. Please scan your face to proceed."
            })

        # ── Verify sender face BEFORE processing transfer ─────────────────
        user = auth_system.validate_session(token)
        if not user:
            return _err("Invalid or expired session.", 401)

        face_check = user_reg.verify_face_from_base64(user["phone"], face_b64, tolerance=0.55)
        if not face_check.get("verified"):
            err_msg = face_check.get("error", "Face verification failed.")
            _log_access("TRANSFER_FACE_FAIL", user.get("phone",""), user.get("name",""),
                        "user", "FAILED", err_msg[:200])
            return _ok({
                "success"      : False,
                "face_required": True,
                "action"       : "FACE_FAILED",
                "message"      : f"Face verification failed: {err_msg} Transaction blocked."
            })

        result = transfer_system.initiate_transfer(
            session_token   = token,
            recipient_phone = recipient_phone,
            amount          = amount,
            transfer_type   = transfer_type,
            face_base64     = face_b64,
        )

        # Abroad pending — not a failure, just pending owner approval
        if result.get("action") == "ABROAD_PENDING":
            return _ok(result)

        code = 200 if result.get("success") or result.get("face_required") else 400
        return _ok(result, code)

    except Exception as e:
        return _err(f"Transfer failed: {e}", 500)


@app.route("/api/calculate-fee", methods=["POST"])
def calculate_fee():
    try:
        data   = request.get_json() or {}
        phone  = data.get("phone", "").strip()
        amount = float(data.get("amount", 0))
        result = transfer_system.get_transfer_fee(phone, amount)
        return _ok(result) if result["success"] else _err(result["error"])
    except Exception as e:
        return _err(f"Fee calculation failed: {e}", 500)


@app.route("/api/transfer-history", methods=["GET"])
def transfer_history():
    try:
        token = _session_token()
        if not token:
            return _err("Missing Authorization header.", 401)
        limit  = request.args.get("limit", 50, type=int)
        result = transfer_system.get_transfer_history(token, limit)
        return _ok(result) if result["success"] else _err(result["error"])
    except Exception as e:
        return _err(f"Failed to fetch history: {e}", 500)


@app.route("/api/check-recipient", methods=["POST"])
def check_recipient():
    try:
        data  = request.get_json() or {}
        phone = data.get("phone", "").strip()
        if not phone:
            return _err("Phone number required.")

        conn = psycopg2.connect(**DB_CONFIG)
        c    = conn.cursor()
        c.execute("SELECT full_name, is_active FROM users WHERE phone_number=%s", (phone,))
        row = c.fetchone()

        if not row:
            conn.close()
            return _ok({"success": True, "registered": False})

        full_name, is_active = row[0], bool(row[1])

        if not is_active:
            import datetime
            today = datetime.date.today().isoformat()
            c.execute("""
                SELECT destination_country, return_date FROM travel_records
                WHERE user_phone=%s
                  AND departure_date::date <= %s::date
                  AND return_date::date    >= %s::date
                ORDER BY id DESC LIMIT 1
            """, (phone, today, today))
            travel = c.fetchone()
            conn.close()
            if travel:
                return _ok({"success": True, "registered": True, "name": full_name,
                            "blocked": True,
                            "blocked_reason": f"✈️ Recipient is abroad in {travel[0]} until {travel[1]}."})
            return _ok({"success": True, "registered": True, "name": full_name,
                        "blocked": True, "blocked_reason": "This account is deactivated."})

        conn.close()
        return _ok({"success": True, "registered": True, "name": full_name, "blocked": False})
    except Exception as e:
        return _err(f"Recipient lookup failed: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# TRAVEL ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/travel/register", methods=["POST"])
def register_travel():
    try:
        data = request.get_json() or {}
        for f in ("phone_number", "departure_date", "return_date", "destination_country"):
            if not data.get(f):
                return _err(f"Missing required field: {f}")
        result = travel_system.register_travel(
            data["phone_number"], data["departure_date"],
            data["return_date"], data["destination_country"])
        return _ok(result) if result["success"] else _err(result["error"])
    except Exception as e:
        return _err(f"Travel registration failed: {e}", 500)


@app.route("/api/travel/reactivate", methods=["POST"])
def reactivate_sim():
    try:
        data  = request.get_json() or {}
        phone = data.get("phone_number", "").strip()
        if not phone:
            return _err("phone_number required.")
        result = travel_system.reactivate_on_return(phone)
        return _ok(result) if result["success"] else _err(result["error"])
    except Exception as e:
        return _err(f"Reactivation failed: {e}", 500)


@app.route("/api/travel/status/<phone>", methods=["GET"])
def travel_status(phone):
    try:
        return _ok({"success": True, "travel": travel_system.get_travel_status(phone)})
    except Exception as e:
        return _err(f"Travel status failed: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# ABROAD TRANSFER VERIFICATION  (owner approves pending transfer via email link)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/abroad-verify/info", methods=["GET"])
def abroad_verify_info():
    """
    Return details of a pending abroad transfer by token.
    Called when the abroad owner opens the verification link.
    """
    try:
        token = request.args.get("token", "").strip()
        if not token:
            return _err("Token is required.")

        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            SELECT apt.id, apt.recipient_phone, apt.amount, apt.fee,
                   apt.destination, apt.expires_at, apt.status,
                   u.full_name, u.email, u.phone_number
            FROM abroad_pending_transfers apt
            JOIN users u ON apt.sender_id = u.id
            WHERE apt.verify_token = %s
        ''', (token,))
        row = c.fetchone()
        conn.close()

        if not row:
            return _err("Invalid or expired verification link.", 404)

        pid, recipient_phone, amount, fee, destination, expires_at, status, \
            owner_name, owner_email, owner_phone = row

        from datetime import datetime as _dt
        if status != 'pending':
            return _ok({
                "success": False,
                "status": status,
                "message": f"This transfer has already been {status}."
            })
        if _dt.now() > expires_at:
            return _ok({
                "success": False,
                "status": "expired",
                "message": "This verification link has expired."
            })

        return _ok({
            "success"        : True,
            "token"          : token,
            "owner_name"     : owner_name,
            "owner_phone"    : owner_phone,
            "recipient_phone": recipient_phone,
            "amount"         : amount,
            "fee"            : fee,
            "total"          : amount + fee,
            "destination"    : destination,
            "expires_at"     : expires_at.isoformat() if expires_at else None,
        })
    except Exception as e:
        return _err(f"Abroad verify info failed: {e}", 500)


@app.route("/api/abroad-verify/confirm", methods=["POST"])
def abroad_verify_confirm():
    """
    Abroad owner scans face to approve the pending transfer.
    Steps:
      1. Validate token → load pending transfer
      2. Verify face against owner's stored encoding
      3. On match → complete the transfer
      4. On fail  → block the transfer, raise fraud alert
    """
    try:
        data     = request.get_json() or {}
        token    = data.get("token", "").strip()
        face_b64 = data.get("face_base64", "")

        if not token:
            return _err("Token is required.")
        if not face_b64:
            return _err("Face scan is required to approve this transfer.")

        # Load the pending transfer
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''
            SELECT apt.id, apt.recipient_phone, apt.amount, apt.fee,
                   apt.destination, apt.expires_at, apt.status,
                   u.id as sender_id, u.full_name, u.phone_number, u.email
            FROM abroad_pending_transfers apt
            JOIN users u ON apt.sender_id = u.id
            WHERE apt.verify_token = %s
        ''', (token,))
        row = c.fetchone()
        conn.close()

        if not row:
            return _err("Invalid or expired verification link.", 404)

        pid, recipient_phone, amount, fee, destination, expires_at, status, \
            sender_id, owner_name, owner_phone, owner_email = row

        from datetime import datetime as _dt
        if status != 'pending':
            return _ok({"success": False, "status": status,
                        "message": f"This transfer has already been {status}."})
        if _dt.now() > expires_at:
            return _ok({"success": False, "status": "expired",
                        "message": "This verification link has expired."})

        # Verify face against owner's stored encoding
        face_result = user_reg.verify_face_from_base64(owner_phone, face_b64, tolerance=0.55)

        if not face_result.get("verified"):
            # Face failed — block the transfer, raise alert
            conn2 = get_db_connection()
            c2 = conn2.cursor()
            c2.execute("UPDATE abroad_pending_transfers SET status='blocked' WHERE id=%s", (pid,))
            conn2.commit(); conn2.close()

            try:
                fraud_detector.alert_sys.raise_alert(
                    owner_phone, amount, 0.95, "HIGH", "BLOCK",
                    f"Abroad transfer face verification FAILED — transfer blocked. "
                    f"Recipient: {recipient_phone}, Amount: {amount:,.0f} RWF, "
                    f"Destination: {destination}. Owner face did not match."
                )
            except Exception:
                pass

            _log_access("ABROAD_VERIFY_FAIL", owner_phone, owner_name,
                        "user", "FAILED",
                        face_result.get("error", "Face mismatch")[:200])

            return _ok({
                "success": False,
                "action" : "BLOCKED",
                "message": (
                    f"Face verification failed. Transfer has been BLOCKED. "
                    f"If this was you, please contact support. "
                    f"Error: {face_result.get('error', 'Face did not match')}"
                )
            })

        # Face matched — complete the transfer
        result = transfer_system.complete_abroad_transfer(token)

        if result["success"]:
            _log_access("ABROAD_VERIFY_OK", owner_phone, owner_name,
                        "user", "SUCCESS",
                        f"Abroad face-verified transfer approved: {amount:,.0f} RWF → {recipient_phone}")
        return _ok(result)

    except Exception as e:
        return _err(f"Abroad verification failed: {e}", 500)

@app.route("/api/dashboard/stats", methods=["GET"])
def dashboard_stats():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        c    = conn.cursor()

        def q(sql):
            c.execute(sql)
            return c.fetchone()[0]

        stats = {
            "total_users"            : q("SELECT COUNT(*) FROM users WHERE email NOT LIKE '%@admin.com'"),
            "active_users"           : q("SELECT COUNT(*) FROM users WHERE is_active=TRUE"),
            "active_providers"       : q("SELECT COUNT(*) FROM service_providers WHERE is_active=TRUE"),
            "users_abroad"           : q(
                "SELECT COUNT(*) FROM travel_records "
                "WHERE departure_date<=NOW() AND return_date>=NOW()"),
            "transfers_today"        : q(
                "SELECT COUNT(*) FROM money_transfers "
                "WHERE created_at::date=CURRENT_DATE"),
            "transfers_7d"           : q(
                "SELECT COUNT(*) FROM money_transfers "
                "WHERE created_at>=NOW()-INTERVAL '7 days'"),
            "fraud_blocked_7d"       : q(
                "SELECT COUNT(*) FROM money_transfers "
                "WHERE is_fraud=TRUE AND created_at>=NOW()-INTERVAL '7 days'"),
            "face_verified_transfers": q(
                "SELECT COUNT(*) FROM money_transfers WHERE face_verified=TRUE"),
            "total_volume_7d"        : q(
                "SELECT COALESCE(SUM(amount),0) FROM money_transfers "
                "WHERE status='completed' AND created_at>=NOW()-INTERVAL '7 days'"),
            "fraud_alerts"           : q(
                "SELECT COUNT(*) FROM fraud_alerts WHERE acknowledged=FALSE")
                if _table_exists(conn, "fraud_alerts") else 0,
        }

        transfers_7d = stats["transfers_7d"] or 1
        stats["fraud_rate_7d"] = round(stats["fraud_blocked_7d"] / transfers_7d * 100, 2)

        conn.close()
        return _ok({"success": True, "stats": stats})
    except Exception as e:
        return _err(f"Stats failed: {e}", 500)


@app.route("/api/fraud/alerts", methods=["GET"])
def fraud_alerts():
    try:
        alerts = fraud_detector.get_fraud_alerts()
        return _ok({"success": True, "alerts": alerts})
    except Exception as e:
        return _err(f"Failed to fetch alerts: {e}", 500)


@app.route("/api/fraud/alerts/acknowledge", methods=["POST"])
def acknowledge_alert():
    try:
        data     = request.get_json() or {}
        alert_id = data.get("alert_id")
        if not alert_id:
            return _err("alert_id required.")
        result = fraud_detector.acknowledge_alert(int(alert_id))
        return _ok(result)
    except Exception as e:
        return _err(f"Acknowledge failed: {e}", 500)


@app.route("/api/pin/attempt", methods=["POST"])
def pin_attempt():
    try:
        data = request.get_json() or {}
        if not data.get("phone_number") or "was_successful" not in data:
            return _err("phone_number and was_successful required.")
        result = pin_monitor.record_pin_attempt(
            data["phone_number"], bool(data["was_successful"]),
            data.get("ip_address"), data.get("device_id"))
        return _ok(result)
    except Exception as e:
        return _err(f"PIN attempt logging failed: {e}", 500)


@app.route("/api/pin/status/<phone>", methods=["GET"])
def pin_status(phone):
    try:
        status = pin_monitor.get_pin_security_status(phone)
        return _ok({"success": True, "pin_security": status})
    except Exception as e:
        return _err(f"PIN status failed: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN USER MANAGEMENT ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/admin/user-lookup", methods=["POST"])
def admin_user_lookup():
    try:
        data  = request.get_json() or {}
        phone = data.get("phone_number", "").strip()
        if not phone:
            return _err("phone_number required.")

        conn = psycopg2.connect(**DB_CONFIG)
        c    = conn.cursor()

        c.execute(
            "SELECT full_name, phone_number, email, national_id, account_balance, is_active "
            "FROM users WHERE phone_number=%s", (phone,))

        user_row = c.fetchone()
        if not user_row:
            conn.close()
            return _err("User not found.")

        user = {
            "name": user_row[0], "phone": user_row[1],
            "email": user_row[2] if len(user_row) > 2 else "",
            "national_id": user_row[3] if len(user_row) > 3 else "",
            "balance": user_row[4] if len(user_row) > 4 else 0,
            "is_active": bool(user_row[5]) if len(user_row) > 5 else True
        }

        try:
            c.execute(
                "SELECT u2.phone_number, mt.recipient_phone, mt.amount, COALESCE(mt.fee,0), "
                "mt.status, mt.created_at, mt.fraud_score, mt.risk_level, mt.is_fraud, "
                "mt.notes, 'sent' "
                "FROM money_transfers mt JOIN users u2 ON mt.sender_id=u2.id "
                "WHERE u2.phone_number=%s ORDER BY mt.created_at DESC LIMIT 20", (phone,))
            sent_rows = c.fetchall()
            c.execute(
                "SELECT u2.phone_number, mt.recipient_phone, mt.amount, 0, mt.status, "
                "mt.created_at, mt.fraud_score, mt.risk_level, mt.is_fraud, mt.notes, 'received' "
                "FROM money_transfers mt JOIN users u2 ON mt.sender_id=u2.id "
                "WHERE mt.recipient_phone=%s AND mt.status='completed' "
                "ORDER BY mt.created_at DESC LIMIT 20", (phone,))
            recv_rows = c.fetchall()
            all_rows = sorted(list(sent_rows) + list(recv_rows), key=lambda x: x[5] or "", reverse=True)
            user["transactions"] = [{
                "sender_phone": r[0], "recipient_phone": r[1], "amount": r[2],
                "fee": r[3], "status": r[4], "created_at": r[5],
                "fraud_score": r[6], "risk_level": r[7], "is_fraud": bool(r[8]),
                "notes": r[9], "direction": r[10]
            } for r in all_rows[:20]]
        except Exception:
            user["transactions"] = []

        if _table_exists(conn, "fraud_alerts"):
            try:
                c.execute(
                    "SELECT message, fraud_score, risk_level, action, created_at "
                    "FROM fraud_alerts WHERE phone_number=%s "
                    "ORDER BY created_at DESC LIMIT 10", (phone,))
                user["alerts"] = [{"message": r[0], "fraud_score": r[1],
                                   "risk_level": r[2], "action": r[3], "created_at": r[4]}
                                  for r in c.fetchall()]
            except Exception:
                user["alerts"] = []

        conn.close()
        return _ok({"success": True, "user": user})
    except Exception as e:
        return _err(f"User lookup failed: {e}", 500)


@app.route("/api/admin/users", methods=["GET"])
@app.route("/api/admin/all-users", methods=["GET"])
def admin_all_users():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        c    = conn.cursor()
        c.execute(
            "SELECT full_name, phone_number, email, account_balance, is_active, national_id, gender "
            "FROM users WHERE email NOT LIKE '%@admin.com' ORDER BY registration_date DESC"
        )
        users = [{"full_name": r[0], "phone_number": r[1], "email": r[2],
                  "account_balance": r[3], "is_active": bool(r[4]),
                  "national_id": r[5], "sex": r[6]}
                 for r in c.fetchall()]
        conn.close()
        return _ok({"success": True, "users": users})
    except Exception as e:
        return _err(f"Failed to fetch users: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN PROVIDER MANAGEMENT ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/admin/providers", methods=["GET"])
def admin_get_providers():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute(
            "SELECT id, name, email, phone, national_id, sex, is_active, created_at "
            "FROM service_providers ORDER BY created_at DESC"
        )
        providers = [
            {"id": r[0], "name": r[1], "email": r[2], "phone": r[3],
             "national_id": r[4], "sex": r[5], "is_active": bool(r[6]), "created_date": r[7]}
            for r in c.fetchall()
        ]
        conn.close()
        return _ok({"success": True, "providers": providers})
    except Exception as e:
        return _err(f"Failed to fetch providers: {e}", 500)


@app.route("/api/admin/add-provider", methods=["POST"])
def admin_add_provider():
    try:
        data = request.get_json() or {}
        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        phone = data.get("phone", "").strip()
        national_id = data.get("national_id", "").strip()
        sex = data.get("sex", "").strip()
        status = data.get("status", "1")
        password = data.get("password", "")
        
        if not all([name, email, password]):
            return _err("Name, email, and password are required.")
        
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        
        c.execute("SELECT id FROM service_providers WHERE email=%s", (email,))
        if c.fetchone():
            conn.close()
            return _err("Email already exists.")
        
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        c.execute(
            "INSERT INTO service_providers (name, email, phone, national_id, sex, password, is_active, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())",
            (name, email, phone, national_id, sex, hashed_password, bool(int(status)))
        )
        
        conn.commit()
        conn.close()
        
        return _ok({
            "success": True,
            "message": "Provider added successfully"
        })
    except Exception as e:
        return _err(f"Failed to add provider: {e}", 500)


@app.route("/api/admin/toggle-provider", methods=["POST"])
def admin_toggle_provider():
    try:
        data = request.get_json() or {}
        provider_id = data.get("provider_id")
        
        if not provider_id:
            return _err("Provider ID is required.")
        
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        
        c.execute("SELECT is_active FROM service_providers WHERE id=%s", (provider_id,))
        result = c.fetchone()
        if not result:
            conn.close()
            return _err("Provider not found.")
        
        new_status = not result[0]
        c.execute("UPDATE service_providers SET is_active=%s WHERE id=%s", (new_status, provider_id))
        conn.commit()
        conn.close()
        
        status_text = "activated" if new_status else "deactivated"
        return _ok({
            "success": True,
            "message": f"Provider {status_text} successfully"
        })
    except Exception as e:
        return _err(f"Failed to toggle provider: {e}", 500)


@app.route("/api/admin/update-provider", methods=["POST"])
def admin_update_provider():
    try:
        data = request.get_json() or {}
        provider_id = data.get("provider_id")
        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        phone = data.get("phone", "").strip()
        national_id = data.get("national_id", "").strip()
        sex = data.get("sex", "").strip()
        status = data.get("status", "1")
        password = data.get("password", "")
        
        if not all([provider_id, name, email]):
            return _err("Provider ID, name, and email are required.")
        
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        
        c.execute("SELECT id FROM service_providers WHERE id=%s", (provider_id,))
        if not c.fetchone():
            conn.close()
            return _err("Provider not found.")
        
        c.execute("SELECT id FROM service_providers WHERE email=%s AND id!=%s", (email, provider_id))
        if c.fetchone():
            conn.close()
            return _err("Email is already used by another provider.")
        
        if password:
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            c.execute(
                "UPDATE service_providers SET name=%s, email=%s, phone=%s, national_id=%s, sex=%s, password=%s, is_active=%s WHERE id=%s",
                (name, email, phone, national_id, sex, hashed_password, bool(int(status)), provider_id)
            )
        else:
            c.execute(
                "UPDATE service_providers SET name=%s, email=%s, phone=%s, national_id=%s, sex=%s, is_active=%s WHERE id=%s",
                (name, email, phone, national_id, sex, bool(int(status)), provider_id)
            )
        
        conn.commit()
        conn.close()
        
        return _ok({
            "success": True,
            "message": "Provider updated successfully"
        })
    except Exception as e:
        return _err(f"Failed to update provider: {e}", 500)


@app.route("/api/admin/delete-provider", methods=["POST"])
def admin_delete_provider():
    try:
        data = request.get_json() or {}
        provider_id = data.get("provider_id")
        
        if not provider_id:
            return _err("Provider ID is required.")
        
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        
        c.execute("DELETE FROM service_providers WHERE id=%s", (provider_id,))
        if c.rowcount == 0:
            conn.close()
            return _err("Provider not found.")
        
        conn.commit()
        conn.close()
        
        return _ok({
            "success": True,
            "message": "Provider deleted successfully"
        })
    except Exception as e:
        return _err(f"Failed to delete provider: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN USER MANAGEMENT ROUTES (EXTENDED)
from datetime import timezone, timedelta

EAT = timedelta(hours=3)

@app.route("/api/admin/access-logs", methods=["GET"])
def admin_get_access_logs():
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT id, event_type, identifier, full_name, role,
                   ip_address, status, detail, created_at
            FROM access_logs
            ORDER BY created_at DESC
            LIMIT %s
        """, (limit,))
        rows = c.fetchall()
        conn.close()
        logs = [
            {
                "id":         row[0],
                "event_type": row[1],
                "identifier": row[2] or "",
                "full_name":  row[3] or "Unknown",
                "role":       row[4] or "",
                "ip_address": row[5] or "",
                "status":     row[6],
                "detail":     row[7] or "",
                "created_at": row[8].strftime("%d/%m/%Y %H:%M:%S") if row[8] else "—"
            }
            for row in rows
        ]
        return _ok({"success": True, "logs": logs})
    except Exception as e:
        return _err(f"Failed to fetch access logs: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/admin/fraud-alerts", methods=["GET"])
def admin_get_fraud_alerts():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()

        if not _table_exists(conn, "fraud_alerts"):
            conn.close()
            return _ok({"success": True, "alerts": []})

        c.execute("""
            SELECT
                fa.id,
                fa.phone_number,
                fa.amount,
                fa.fraud_score,
                fa.risk_level,
                fa.action,
                fa.alert_message,
                fa.acknowledged,
                fa.created_at,
                u.full_name
            FROM fraud_alerts fa
            LEFT JOIN users u ON fa.phone_number = u.phone_number
            ORDER BY fa.created_at DESC
            LIMIT 100
        """)

        alerts = [
            {
                "id": row[0],
                "phone_number": row[1],
                "amount": row[2],
                "fraud_score": row[3],
                "risk_level": row[4],
                "action": row[5],
                "message": row[6],
                "acknowledged": bool(row[7]),
                "created_at": row[8],
                "user_name": row[9] or "Unknown"
            }
            for row in c.fetchall()
        ]

        conn.close()
        return _ok({
            "success": True,
            "alerts": alerts
        })
    except Exception as e:
        return _err(f"Failed to fetch fraud alerts: {e}", 500)


@app.route("/api/admin/update-user-multi", methods=["POST"])
def admin_update_user_multi():
    try:
        data = request.get_json() or {}
        phone = data.get("phone_number", "").strip()
        full_name = data.get("full_name", "").strip()
        email = data.get("email", "").strip()
        national_id = data.get("national_id", "").strip()
        sex = data.get("sex", "").strip()
        account_balance = data.get("account_balance")
        is_active = data.get("is_active")
        
        if not all([phone, full_name]):
            return _err("Phone number and full name are required.")
        
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        
        c.execute("SELECT phone_number FROM users WHERE phone_number=%s", (phone,))
        if not c.fetchone():
            conn.close()
            return _err("User not found.")
        
        update_fields = []
        update_values = []
        
        update_fields.append("full_name=%s")
        update_values.append(full_name)
        
        if email is not None:
            update_fields.append("email=%s")
            update_values.append(email)
        
        if national_id is not None:
            update_fields.append("national_id=%s")
            update_values.append(national_id)
        
        if sex is not None:
            update_fields.append("gender=%s")
            update_values.append(sex)
        
        if account_balance is not None:
            update_fields.append("account_balance=%s")
            update_values.append(account_balance)
        
        if is_active is not None:
            update_fields.append("is_active=%s")
            update_values.append(bool(is_active))
        
        update_values.append(phone)
        
        c.execute(f"UPDATE users SET {', '.join(update_fields)} WHERE phone_number=%s", update_values)
        conn.commit()
        conn.close()
        
        return _ok({
            "success": True,
            "message": "User updated successfully"
        })
    except Exception as e:
        return _err(f"Failed to update user: {e}", 500)


@app.route("/api/admin/update-user", methods=["POST"])
def admin_update_user():
    try:
        data = request.get_json() or {}
        phone = data.get("phone_number", "").strip()
        field = data.get("field", "").strip()
        value = data.get("value")
        
        if not all([phone, field]):
            return _err("Phone number and field are required.")
        
        valid_fields = ["full_name", "email", "account_balance", "is_active"]
        if field not in valid_fields:
            return _err(f"Invalid field. Must be one of: {', '.join(valid_fields)}")
        
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        
        # Check if user exists
        c.execute("SELECT phone_number FROM users WHERE phone_number=%s", (phone,))
        if not c.fetchone():
            conn.close()
            return _err("User not found.")
        
        # Update user
        if field == "is_active":
            value = True if value else False
        
        c.execute(f"UPDATE users SET {field}=%s WHERE phone_number=%s", (value, phone))
        conn.commit()
        conn.close()
        
        return _ok({
            "success": True,
            "message": "User updated successfully"
        })
    except Exception as e:
        return _err(f"Failed to update user: {e}", 500)


@app.route("/api/admin/delete-user", methods=["POST"])
def admin_delete_user():
    try:
        data = request.get_json() or {}
        phone = data.get("phone_number", "").strip()
        
        if not phone:
            return _err("Phone number is required.")
        
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        
        # Delete user
        c.execute("DELETE FROM users WHERE phone_number=%s", (phone,))
        if c.rowcount == 0:
            conn.close()
            return _err("User not found.")
        
        conn.commit()
        conn.close()
        
        return _ok({
            "success": True,
            "message": "User deleted successfully"
        })
    except Exception as e:
        return _err(f"Failed to delete user: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN SYSTEM MANAGEMENT ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/admin/backup", methods=["POST"])
def admin_create_backup():
    try:
        import shutil
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"backup_{timestamp}.db"
        
        # Create backup
        # PostgreSQL backup via pg_dump
        import subprocess
        result_proc = subprocess.run(
            ["pg_dump", "-U", DB_CONFIG["user"], "-h", DB_CONFIG["host"],
             "-p", DB_CONFIG["port"], "-F", "c", "-f", backup_path, DB_CONFIG["dbname"]],
            capture_output=True, text=True,
            env={**os.environ, "PGPASSWORD": DB_CONFIG["password"]}
        )
        if result_proc.returncode != 0:
            return _err(f"pg_dump failed: {result_proc.stderr}")
        
        return _ok({
            "success": True,
            "message": "Backup created successfully",
            "backup_file": backup_path
        })
    except Exception as e:
        return _err(f"Failed to create backup: {e}", 500)


@app.route("/api/admin/system-stats", methods=["GET"])
def admin_system_stats():
    try:
        import os
        
        # Database size
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute("SELECT pg_database_size(%s)", (DB_CONFIG["dbname"],))
        db_size_mb = round(c.fetchone()[0] / (1024 * 1024), 2)
        conn.close()

        active_user_sessions = len(provider_sessions)
        active_provider_sessions = len(provider_sessions)
        
        # System uptime (simplified)
        uptime_seconds = 3600  # Placeholder
        
        return _ok({
            "success": True,
            "stats": {
                "database_size_mb": db_size_mb,
                "active_user_sessions": active_user_sessions,
                "active_provider_sessions": active_provider_sessions,
                "uptime_seconds": uptime_seconds,
                "system_status": "healthy"
            }
        })
    except Exception as e:
        return _err(f"Failed to get system stats: {e}", 500)


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    return _ok({
        "status"    : "healthy",
        "timestamp" : datetime.now().isoformat(),
        "version"   : "2.0.0",
        "ml_model"  : fraud_detector.config.get("best_model", "not loaded"),
        "threshold" : fraud_detector.config.get("threshold", "—"),
        "fraud_f1"  : fraud_detector.config.get("fraud_f1", "—"),
    })


@app.errorhandler(404)
def not_found(e):
    return _err("Endpoint not found.", 404)

@app.errorhandler(413)
def too_large(e):
    return _err("File too large (max 16 MB).", 413)

@app.errorhandler(500)
def server_error(e):
    return _err("Internal server error.", 500)


# ── User convenience aliases (frontend uses /api/user/* prefix) ──────────────

@app.route("/api/user/balance", methods=["POST"])
def user_balance():
    try:
        data = request.get_json() or {}
        token = data.get("session_token") or _session_token()  # ← accept both
        if not token:
            return _err("Missing session token.", 401)
        user = auth_system.validate_session(token)
        if not user:
            return _err("Invalid session.", 401)
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute("SELECT account_balance FROM users WHERE phone_number=%s", (user["phone"],))
        row = c.fetchone()
        conn.close()
        return _ok({"success": True, "balance": row[0] if row else 0})
    except Exception as e:
        return _err(f"Balance fetch failed: {e}", 500)


@app.route("/api/user/history", methods=["POST"])
def user_history_post():
    data = request.get_json() or {}
    token = data.get("session_token") or _session_token()
    if not token:
        return _err("Missing session token.", 401)
    limit = data.get("limit", 50)
    result = transfer_system.get_transfer_history(token, limit)
    if result["success"]:
        # rename "transfers" → "history" so frontend can read d.history
        result["history"] = result.pop("transfers", [])
        return _ok(result)
    return _err(result["error"])


@app.route("/api/user/profile", methods=["POST"])
def user_profile():
    try:
        data = request.get_json() or {}
        token = data.get("session_token") or _session_token()  # ← accept both
        if not token:
            return _err("Missing session token.", 401)
        user = auth_system.validate_session(token)
        if not user:
            return _err("Invalid session.", 401)
        conn = psycopg2.connect(**DB_CONFIG)
        c = conn.cursor()
        c.execute(
            "SELECT full_name, email, phone_number, national_id, account_balance, gender FROM users WHERE phone_number=%s",
            (user["phone"],)
        )
        row = c.fetchone()
        conn.close()
        if not row:
            return _err("User not found.")
        return _ok({"success": True, "user": {   # ← key must be "user" not "profile"
            "name": row[0], "email": row[1], "phone": row[2],
            "national_id": row[3], "balance": row[4], "sex": row[5]
        }})
    except Exception as e:
        return _err(f"Profile fetch failed: {e}", 500)


@app.route("/api/user/lookup", methods=["POST"])
def user_lookup():
    return check_recipient()  # reuse existing logic


# Aliases for paths the frontend uses with /api/user/ prefix
@app.route("/api/user/verify-identity", methods=["POST"])
def user_verify_identity():
    return verify_identity()

@app.route("/api/user/reset-pin", methods=["POST"])
def user_reset_pin():
    return reset_pin()

@app.route("/api/user/update-face", methods=["POST"])
def user_update_face():
    return update_face()  


@app.route('/api/admin/user-transactions', methods=['POST'])
def admin_user_transactions():
    data = request.get_json() or {}
    phone_number = data.get('phone_number', '').strip()
    if not phone_number:
        return jsonify({'success': False, 'error': 'Phone number required'}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor()

        # Sent transactions
        c.execute("""
            SELECT u.phone_number AS sender_phone, mt.recipient_phone, mt.amount,
                   COALESCE(mt.fee, 0) AS fee, mt.status, mt.created_at,
                   mt.fraud_score, mt.risk_level, mt.is_fraud, mt.notes
            FROM money_transfers mt
            JOIN users u ON mt.sender_id = u.id
            WHERE u.phone_number = %s
            ORDER BY mt.created_at DESC
            LIMIT 30
        """, (phone_number,))
        sent = [{'sender_phone': r[0], 'receiver_phone': r[1], 'amount': r[2],
                 'fee': r[3], 'status': r[4],
                 'created_at': r[5].isoformat() if r[5] else None,
                 'fraud_score': r[6], 'risk_level': r[7],
                 'is_fraud': bool(r[8]), 'notes': r[9]} for r in c.fetchall()]

        # Received transactions
        c.execute("""
            SELECT u.phone_number AS sender_phone, mt.recipient_phone, mt.amount,
                   0 AS fee, mt.status, mt.created_at,
                   mt.fraud_score, mt.risk_level, mt.is_fraud, mt.notes
            FROM money_transfers mt
            JOIN users u ON mt.sender_id = u.id
            WHERE mt.recipient_phone = %s AND mt.status = 'completed'
            ORDER BY mt.created_at DESC
            LIMIT 30
        """, (phone_number,))
        received = [{'sender_phone': r[0], 'receiver_phone': r[1], 'amount': r[2],
                     'fee': r[3], 'status': r[4],
                     'created_at': r[5].isoformat() if r[5] else None,
                     'fraud_score': r[6], 'risk_level': r[7],
                     'is_fraud': bool(r[8]), 'notes': r[9]} for r in c.fetchall()]

        conn.close()

        # Merge and sort by date
        all_tx = sorted(sent + received,
                        key=lambda x: x['created_at'] or '', reverse=True)[:50]

        return jsonify({'success': True, 'transactions': all_tx})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/user-fraud-alerts', methods=['POST'])
def admin_user_fraud_alerts():
    data = request.get_json() or {}
    phone_number = data.get('phone_number', '').strip()
    if not phone_number:
        return jsonify({'success': False, 'error': 'Phone number required'}), 400

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            SELECT id, phone_number, amount, fraud_score, risk_level,
                   action, alert_message, acknowledged, created_at
            FROM fraud_alerts
            WHERE phone_number = %s
            ORDER BY created_at DESC
            LIMIT 50
        """, (phone_number,))
        alerts = [{'id': r[0], 'phone_number': r[1], 'amount': r[2],
                   'fraud_score': r[3], 'risk_level': r[4], 'action': r[5],
                   'message': r[6], 'acknowledged': bool(r[7]),
                   'created_at': r[8].isoformat() if r[8] else None}
                  for r in c.fetchall()]
        conn.close()
        return jsonify({'success': True, 'alerts': alerts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500     


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Mobile Money Fraud Detection API  v2.0")
    print("=" * 60)
    print(f"  URL      : http://localhost:5000")
    print(f"  Health   : http://localhost:5000/api/health")
    print(f"  Dashboard: http://localhost:5000/user_dashboard")
    print(f"  ML Model : {fraud_detector.config.get('best_model', 'not loaded')}")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True, use_reloader=False)
