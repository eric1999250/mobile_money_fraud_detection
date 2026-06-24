"""
fraud_detection.py — Mobile Money Fraud Detection System
=========================================================
Classes:
  - UserRegistrationSystem   : register users with face encoding
  - TravelMonitoringSystem   : detect abroad users, block SIM transfers
  - TransactionAnomalyDetector: rule-based anomaly scoring from history
  - PinMonitoringSystem      : detect brute-force PIN attempts
  - RealTimeFraudDetector    : ML-powered fraud scoring + face verification gate
  - FraudAlertSystem         : notify service provider when fraud suspected
"""

import psycopg2
import psycopg2.extras
import numpy as np
import pandas as pd
import joblib
import json
import base64
import os
from datetime import datetime, timedelta


# ─────────────────────────────────────────────────────────────────────────────
# 1. USER REGISTRATION SYSTEM  (phone ↔ name ↔ face mapping)
# ─────────────────────────────────────────────────────────────────────────────
class UserRegistrationSystem:
    def __init__(self, db_config):
        self.db_config = db_config
        self.init_database()
    
    def get_connection(self):
        """Create and return a PostgreSQL database connection."""
        return psycopg2.connect(**self.db_config)

    def init_database(self):
        """Create all required tables if they do not exist."""
        conn = self.get_connection()
        c = conn.cursor()

        # Main users table — phone ↔ name ↔ face mapping
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id                  SERIAL PRIMARY KEY,
                phone_number        TEXT    UNIQUE NOT NULL,
                full_name           TEXT    NOT NULL,
                national_id         TEXT    UNIQUE NOT NULL,
                email               TEXT    UNIQUE NOT NULL,
                password_hash       TEXT    DEFAULT '',
                salt                TEXT    DEFAULT '',
                gender              TEXT    DEFAULT '',
                registration_date   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active           BOOLEAN DEFAULT TRUE,
                face_encoding       BYTEA,
                face_image_path     TEXT,
                verification_status TEXT    DEFAULT 'pending',
                account_balance     REAL    DEFAULT 0.0,
                last_login          TIMESTAMP
            )
        ''')

        # Travel monitoring
        c.execute('''
            CREATE TABLE IF NOT EXISTS travel_records (
                id                  SERIAL PRIMARY KEY,
                user_phone          TEXT,
                departure_date      TIMESTAMP,
                return_date         TIMESTAMP,
                destination_country TEXT,
                sim_deactivated     BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_phone) REFERENCES users (phone_number)
            )
        ''')

        # Transaction history for pattern analysis
        c.execute('''
            CREATE TABLE IF NOT EXISTS transaction_history (
                id               SERIAL PRIMARY KEY,
                user_phone       TEXT,
                amount           REAL,
                transaction_type TEXT,
                timestamp        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                recipient_phone  TEXT,
                is_fraud         BOOLEAN DEFAULT FALSE,
                fraud_score      REAL,
                FOREIGN KEY (user_phone) REFERENCES users (phone_number)
            )
        ''')

        # PIN attempt monitoring
        c.execute('''
            CREATE TABLE IF NOT EXISTS pin_attempts (
                id             SERIAL PRIMARY KEY,
                user_phone     TEXT,
                attempt_time   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                was_successful BOOLEAN DEFAULT FALSE,
                ip_address     TEXT,
                device_id      TEXT,
                FOREIGN KEY (user_phone) REFERENCES users (phone_number)
            )
        ''')

        # Pending deposits table
        c.execute('''
            CREATE TABLE IF NOT EXISTS pending_deposits (
                id         SERIAL PRIMARY KEY,
                user_id    INTEGER,
                amount     REAL,
                reference  TEXT,
                status     TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')

        # Safe migration: add gender column if missing
        try:
            c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS gender TEXT DEFAULT ''")
        except Exception:
            pass

        conn.commit()
        c.close()
        conn.close()

    # ── Face encoding helpers ─────────────────────────────────────────────

    # ── Landmark completeness check ───────────────────────────────────────

    def _check_face_completeness(self, face_landmarks: dict) -> dict:
        """
        Verify that the face has all required visible features:
        eyes (left + right), eyebrows, nose, mouth/lips, and chin.
        Returns {"complete": bool, "missing": list, "error": str|None}
        """
        required_features = {
            "left_eye"      : "left eye",
            "right_eye"     : "right eye",
            "left_eyebrow"  : "left eyebrow",
            "right_eyebrow" : "right eyebrow",
            "nose_bridge"   : "nose bridge",
            "nose_tip"      : "nose tip",
            "top_lip"       : "mouth / upper lip",
            "bottom_lip"    : "mouth / lower lip",
            "chin"          : "chin",
        }
        missing = []
        for key, label in required_features.items():
            pts = face_landmarks.get(key, [])
            if not pts or len(pts) < 2:
                missing.append(label)

        if missing:
            parts_str = ", ".join(missing)
            return {
                "complete": False,
                "missing" : missing,
                "error"   : (
                    f"Incomplete face detected — these features are not visible: {parts_str}. "
                    "Please ensure your full face (eyes, nose, mouth) is clearly visible, "
                    "well-lit, and facing the camera directly."
                )
            }
        return {"complete": True, "missing": [], "error": None}

    def validate_face_quality_only(self, base64_str: str) -> dict:
        """
        Run all quality checks (brightness, size, landmarks, eyes, upright)
        and return encoding bytes — but NEVER save to disk or DB.
        Used by /api/validate-face for Reset PIN and fraud face gate.
        Returns { encoding: bytes|None, error: str|None, face_count, face_size }
        """
        try:
            import face_recognition
            import io
            from PIL import Image

            img_bytes = base64.b64decode(base64_str)
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            img_array = np.array(img)

            avg_brightness = img_array.mean()
            if avg_brightness < 30:
                return {"encoding": None, "error": "Image is too dark. Please improve lighting and try again.", "face_count": 0}
            if avg_brightness > 245:
                return {"encoding": None, "error": "Image is overexposed. Reduce lighting or move away from direct light.", "face_count": 0}

            face_locations = face_recognition.face_locations(img_array, model="hog")
            if not face_locations:
                return {"encoding": None, "error": "No face detected. Ensure your face is centred, well-lit, and not obscured.", "face_count": 0}
            if len(face_locations) > 1:
                return {"encoding": None, "error": "Multiple faces detected. Only your face should be in the frame.", "face_count": len(face_locations)}

            top, right, bottom, left = face_locations[0]
            face_width  = right - left
            face_height = bottom - top
            if face_width < 80 or face_height < 80:
                return {"encoding": None, "error": f"Face too small ({face_width}×{face_height}px). Move closer to the camera.", "face_count": 1}

            img_h, img_w = img_array.shape[:2]
            if (face_width * face_height) / (img_w * img_h) < 0.08:
                return {"encoding": None, "error": "Face too far from camera. Move closer so your face fills the frame.", "face_count": 1}

            margin = 10
            if top < margin or left < margin or right > img_w - margin or bottom > img_h - margin:
                return {"encoding": None, "error": "Face is too close to the edge. Centre your face in the frame.", "face_count": 1}

            all_landmarks = face_recognition.face_landmarks(img_array, face_locations)
            if not all_landmarks:
                return {"encoding": None, "error": "Could not detect facial landmarks. Face the camera directly.", "face_count": 1}

            lm_check = self._check_face_completeness(all_landmarks[0])
            if not lm_check["complete"]:
                return {"encoding": None, "error": lm_check["error"], "face_count": 1}

            lm = all_landmarks[0]
            def _eye_open(pts):
                if not pts or len(pts) < 4: return 1.0
                xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
                w = max(xs) - min(xs); h = max(ys) - min(ys)
                return h / w if w > 0 else 1.0

            if _eye_open(lm.get("left_eye", [])) < 0.10 and _eye_open(lm.get("right_eye", [])) < 0.10:
                return {"encoding": None, "error": "Eyes appear closed. Look directly at the camera with eyes open.", "face_count": 1}

            nose_pts = lm.get("nose_tip", []); chin_pts = lm.get("chin", [])
            if nose_pts and chin_pts:
                nose_y = sum(p[1] for p in nose_pts) / len(nose_pts)
                chin_y = sum(p[1] for p in chin_pts) / len(chin_pts)
                if chin_y < nose_y:
                    return {"encoding": None, "error": "Hold your head upright and face the camera directly.", "face_count": 1}

            encodings = face_recognition.face_encodings(img_array, face_locations)
            if not encodings:
                return {"encoding": None, "error": "Failed to generate face encoding. Try again with better lighting.", "face_count": 1}

            # Return encoding bytes — no disk write
            return {
                "encoding": encodings[0].tobytes(),
                "error": None,
                "face_count": 1,
                "face_size": f"{face_width}×{face_height}",
            }

        except ImportError:
            return {
                "encoding": None,
                "error": (
                    "Face recognition library is not installed on this server. "
                    "Face verification is unavailable — action blocked for security. "
                    "Please contact support."
                ),
                "face_count": 0,
            }
        except Exception as e:
            return {"encoding": None, "error": f"Image processing error: {e}", "face_count": 0}

    def extract_face_encoding_from_base64(self, base64_str: str):
        """
        Extract a face encoding from a base64-encoded image string.
        Requirements enforced:
          1. Exactly one face detected.
          2. Face large enough (≥80×80 px) — quality check.
          3. All facial landmarks visible: eyes, eyebrows, nose, mouth, chin.
          4. Image saved to uploads/ folder AND encoding stored in DB.
        Returns dict with encoding data, image save path, and validation info.
        """
        try:
            import face_recognition
            import io
            from PIL import Image
            import os
            import uuid
            from datetime import datetime

            img_bytes = base64.b64decode(base64_str)
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            img_array = np.array(img)

            # ── 1. Brightness / quality check ────────────────────────────
            avg_brightness = img_array.mean()
            if avg_brightness < 30:
                return {
                    "encoding": None, "image_path": None,
                    "error": "Image is too dark. Please improve lighting and try again.",
                    "face_count": 0
                }
            if avg_brightness > 245:
                return {
                    "encoding": None, "image_path": None,
                    "error": "Image is overexposed (too bright). Reduce lighting or move away from direct light.",
                    "face_count": 0
                }

            # ── 2. Detect face locations ──────────────────────────────────
            face_locations = face_recognition.face_locations(img_array, model="hog")
            if not face_locations:
                return {
                    "encoding": None, "image_path": None,
                    "error": (
                        "No face detected. Please ensure your face is centered, "
                        "well-lit, and not obscured by glasses, mask, or hair."
                    ),
                    "face_count": 0
                }
            if len(face_locations) > 1:
                return {
                    "encoding": None, "image_path": None,
                    "error": "Multiple faces detected. Only your face should be in the frame.",
                    "face_count": len(face_locations)
                }

            # ── 3. Face size / quality gate ───────────────────────────────
            top, right, bottom, left = face_locations[0]
            face_width  = right - left
            face_height = bottom - top
            min_face_px = 80
            if face_width < min_face_px or face_height < min_face_px:
                return {
                    "encoding": None, "image_path": None,
                    "error": (
                        f"Face is too small ({face_width}×{face_height} px). "
                        "Move closer to the camera so your face fills more of the frame."
                    ),
                    "face_count": 1
                }

            # ── 4a. Face must cover enough of the image (not too far away) ─
            img_h, img_w = img_array.shape[:2]
            face_area_ratio = (face_width * face_height) / (img_w * img_h)
            if face_area_ratio < 0.08:
                return {
                    "encoding": None, "image_path": None,
                    "error": (
                        "Your face is too far from the camera. "
                        "Move closer so your face fills most of the frame."
                    ),
                    "face_count": 1
                }

            # ── 4b. Face must not be clipped at image edge ────────────────
            margin = 10  # pixels
            if top < margin or left < margin or right > img_w - margin or bottom > img_h - margin:
                return {
                    "encoding": None, "image_path": None,
                    "error": (
                        "Your face is too close to the edge or partially cut off. "
                        "Centre your face in the frame and try again."
                    ),
                    "face_count": 1
                }

            # ── 4c. Landmark completeness — eyes, nose, mouth must be visible ──
            all_landmarks = face_recognition.face_landmarks(img_array, face_locations)
            if not all_landmarks:
                return {
                    "encoding": None, "image_path": None,
                    "error": (
                        "Could not detect facial landmarks. "
                        "Ensure your full face is visible and facing the camera directly."
                    ),
                    "face_count": 1
                }

            landmark_check = self._check_face_completeness(all_landmarks[0])
            if not landmark_check["complete"]:
                return {
                    "encoding": None, "image_path": None,
                    "error": landmark_check["error"],
                    "face_count": 1
                }

            # ── 4d. Eyes must be open — check eye height ──────────────────
            lm = all_landmarks[0]
            def _eye_openness(eye_pts):
                if not eye_pts or len(eye_pts) < 4:
                    return 1.0
                xs = [p[0] for p in eye_pts]
                ys = [p[1] for p in eye_pts]
                width  = max(xs) - min(xs)
                height = max(ys) - min(ys)
                return height / width if width > 0 else 1.0

            left_open  = _eye_openness(lm.get("left_eye",  []))
            right_open = _eye_openness(lm.get("right_eye", []))
            if left_open < 0.10 and right_open < 0.10:
                return {
                    "encoding": None, "image_path": None,
                    "error": (
                        "Your eyes appear to be closed or looking away. "
                        "Please look directly at the camera with eyes open."
                    ),
                    "face_count": 1
                }

            # ── 4e. Face must be roughly upright — chin below nose ────────
            nose_pts = lm.get("nose_tip", [])
            chin_pts = lm.get("chin", [])
            if nose_pts and chin_pts:
                nose_y = sum(p[1] for p in nose_pts) / len(nose_pts)
                chin_y = sum(p[1] for p in chin_pts) / len(chin_pts)
                if chin_y < nose_y:
                    return {
                        "encoding": None, "image_path": None,
                        "error": (
                            "Please hold your head upright and face the camera directly. "
                            "Avoid tilting your head back."
                        ),
                        "face_count": 1
                    }

            # ── 5. Generate encoding ──────────────────────────────────────
            encodings = face_recognition.face_encodings(img_array, face_locations)
            if not encodings:
                return {
                    "encoding": None, "image_path": None,
                    "error": "Failed to generate face encoding. Try again with better lighting.",
                    "face_count": 1
                }

            # ── 6. Save image to uploads/ folder ─────────────────────────
            uploads_dir = "uploads"
            os.makedirs(uploads_dir, exist_ok=True)

            timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_id  = str(uuid.uuid4())[:8]
            filename   = f"face_{timestamp}_{unique_id}.jpg"
            image_path = os.path.join(uploads_dir, filename)
            img.save(image_path, "JPEG", quality=95)

            print(f"[FaceEncoding] ✅ Face saved → {image_path} | size={face_width}×{face_height}")

            return {
                "encoding"  : encodings[0].tobytes(),
                "image_path": image_path,
                "error"     : None,
                "face_count": 1,
                "face_size" : f"{face_width}×{face_height}",
                "landmarks" : list(landmark_check["missing"]),
            }

        except ImportError:
            return {
                "encoding"  : base64.b64decode(base64_str[:200]),
                "image_path": None,
                "error"     : "Face recognition library not available. Face verification will be disabled.",
                "face_count": 0
            }
        except Exception as e:
            print(f"[FaceEncoding] Error: {e}")
            return {
                "encoding": None, "image_path": None,
                "error"   : f"Image processing error: {str(e)}",
                "face_count": 0
            }

    def verify_face_from_base64(self, phone_number: str, base64_str: str,
                                tolerance: float = 0.55) -> dict:
        """
        Dual-source face verification:
          1. Compare live face against DB-stored encoding.
          2. ALSO compare live face against the saved image in uploads/ folder.
        Both sources must agree (match) for verification to pass.
        Returns {"verified": bool, "distance_db": float, "distance_file": float, ...}
        """
        try:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute("SELECT face_encoding, face_image_path FROM users WHERE phone_number = %s",
                      (phone_number,))
            row = c.fetchone()
            conn.close()

            if not row or not row[0]:
                return {"verified": False, "error": "No face data registered for this user"}
        except Exception as e:
            print(f"[FaceVerify] Database error: {e}")
            return {"verified": False, "error": "Face verification system unavailable"}

        stored_encoding_bytes = row[0]
        stored_image_path     = row[1]   # may be None for old registrations

        try:
            import face_recognition
            import io
            from PIL import Image

            # ── Decode and validate live image ────────────────────────────
            img_bytes  = base64.b64decode(base64_str)
            img        = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            img_array  = np.array(img)

            # Brightness check
            avg_brightness = img_array.mean()
            if avg_brightness < 20 or avg_brightness > 245:
                return {"verified": False,
                        "error": "Image quality too poor (too dark or too bright). Adjust lighting."}

            # Detect face locations
            live_locations = face_recognition.face_locations(img_array, model="hog")
            if not live_locations:
                return {"verified": False, "error": "No face detected in the submitted image."}
            if len(live_locations) > 1:
                return {"verified": False, "error": "Multiple faces detected. Only your face should be visible."}

            # Landmark completeness check on live face
            live_landmarks = face_recognition.face_landmarks(img_array, live_locations)
            if live_landmarks:
                lm_check = self._check_face_completeness(live_landmarks[0])
                if not lm_check["complete"]:
                    return {"verified": False, "error": lm_check["error"]}

            live_encs = face_recognition.face_encodings(img_array, live_locations)
            if not live_encs:
                return {"verified": False, "error": "Could not generate face encoding from submitted image."}
            live_enc = live_encs[0]

            # ── Source 1: Compare against DB encoding ─────────────────────
            stored_enc_db = np.frombuffer(stored_encoding_bytes, dtype=np.float64)
            if len(stored_enc_db) != 128:
                stored_enc_db = np.frombuffer(stored_encoding_bytes, dtype=np.float32).astype(np.float64)

            dist_db  = float(face_recognition.face_distance([stored_enc_db], live_enc)[0])
            match_db = dist_db <= tolerance

            # ── Source 2: Compare against saved folder image ──────────────
            dist_file  = None
            match_file = None

            if stored_image_path and stored_image_path.strip() and os.path.exists(stored_image_path):
                try:
                    saved_img       = Image.open(stored_image_path).convert("RGB")
                    saved_arr       = np.array(saved_img)
                    saved_locations = face_recognition.face_locations(saved_arr, model="hog")
                    if saved_locations:
                        saved_encs = face_recognition.face_encodings(saved_arr, saved_locations)
                        if saved_encs:
                            dist_file  = float(face_recognition.face_distance([saved_encs[0]], live_enc)[0])
                            match_file = dist_file <= tolerance
                except Exception as fe:
                    print(f"[FaceVerify] Folder image comparison error: {fe}")
                    match_file = None
            else:
                # Handle NULL/empty paths for existing users without saved face images
                print(f"[FaceVerify] No saved face image available (user registered before image saving) — using DB encoding only")

            # ── Decision ──────────────────────────────────────────────────
            if match_file is not None:
                verified = match_db and match_file
                source   = "db+folder"
            else:
                verified = match_db
                source   = "db_only"

            result = {
                "verified"      : verified,
                "distance_db"   : round(dist_db, 4),
                "distance_file" : round(dist_file, 4) if dist_file is not None else None,
                "match_db"      : match_db,
                "match_file"    : match_file,
                "tolerance"     : tolerance,
                "source"        : source,
            }

            if not verified:
                if match_file is not None and match_db and not match_file:
                    result["error"] = "Face matched database but not saved image — possible tampering detected."
                elif not match_db:
                    result["error"] = "Face does not match registered identity. Verification failed."

            return result

        except ImportError:
            print("[FaceVerify] face_recognition not installed — BLOCKING verification, never bypassing")
            return {
                "verified": False,
                "error": (
                    "Face verification library is not available on this server. "
                    "Face check cannot be completed — action blocked for security. "
                    "Please contact support."
                )
            }
        except Exception as e:
            return {"verified": False, "error": str(e)}

    # ── Registration ──────────────────────────────────────────────────────

    def register_user_with_face(self, phone_number: str, full_name: str,
                                national_id: str, email: str,
                                password_hash: str, salt: str,
                                gender: str = '',
                                face_base64: str = None) -> dict:
        """
        Register a new user. Face encoding is extracted from base64 image
        captured via the device camera during registration.
        """
        face_encoding = None
        if face_base64:
            face_encoding = self.extract_face_encoding_from_base64(face_base64)

        conn = self.get_connection()
        c = conn.cursor()
        try:
            c.execute('''
                INSERT INTO users
                (phone_number, full_name, national_id, email,
                 password_hash, salt, gender,
                 face_encoding, verification_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (phone_number, full_name, national_id, email,
                  password_hash, salt, gender,
                  face_encoding,
                  'verified' if face_encoding else 'pending'))
            conn.commit()
            return {"success": True,
                    "message": "Account created successfully",
                    "face_registered": face_encoding is not None}
        except psycopg2.IntegrityError:
            return {"success": False,
                    "error": "User with this phone, email, or ID already exists"}
        finally:
            conn.close()

    def update_face_encoding(self, phone_number: str, face_base64: str,
                             overwrite: bool = False) -> dict:
        """
        Update stored face encoding for an existing user.
        If overwrite=True (called from /api/update-face):
          - Deletes the old face image from disk
          - Saves the new image with the SAME filename pattern (one file per user)
          - Updates DB encoding + face_image_path
        If overwrite=False (first-time set):
          - Behaves as before (saves new file)
        """
        # First get existing face_image_path so we can delete it
        existing_path = None
        if overwrite:
            conn = self.get_connection()
            c = conn.cursor()
            c.execute(
                "SELECT face_image_path FROM users WHERE phone_number=%s", (phone_number,)
            )
            row = c.fetchone()
            c.close()
            conn.close()
            if row and row[0]:
                existing_path = row[0]

        face_result = self.extract_face_encoding_from_base64(face_base64)

        if face_result.get("error"):
            return {"success": False, "error": face_result["error"]}
        if not face_result.get("encoding"):
            return {"success": False, "error": "No face detected in provided image"}

        # Delete old file from disk
        if existing_path and os.path.exists(existing_path):
            try:
                os.remove(existing_path)
                print(f"[UpdateFace] Deleted old face image: {existing_path}")
            except Exception as e:
                print(f"[UpdateFace] Could not delete old file: {e}")

        new_path = face_result.get("image_path")
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            UPDATE users
            SET face_encoding = %s, face_image_path = %s, verification_status = 'verified'
            WHERE phone_number = %s
        ''', (face_result["encoding"], new_path, phone_number))
        conn.commit()
        conn.close()
        return {
            "success"   : True,
            "message"   : "Face updated successfully.",
            "image_path": new_path,
            "face_size" : face_result.get("face_size"),
        }

    def get_user_info(self, phone_number: str) -> dict | None:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT phone_number, full_name, national_id, email,
                   registration_date, is_active, verification_status,
                   account_balance, gender
            FROM users WHERE phone_number = %s
        ''', (phone_number,))
        row = c.fetchone()
        conn.close()
        if not row:
            return None
        return {
            "phone_number"       : row[0],
            "full_name"          : row[1],
            "national_id"        : row[2],
            "email"              : row[3],
            "registration_date"  : row[4],
            "is_active"          : bool(row[5]),
            "verification_status": row[6],
            "account_balance"    : row[7],
            "gender"             : row[8],
        }

    def has_face_registered(self, phone_number: str) -> bool:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT face_encoding FROM users WHERE phone_number = %s",
                  (phone_number,))
        row = c.fetchone()
        conn.close()
        return row is not None and row[0] is not None


# ─────────────────────────────────────────────────────────────────────────────
# 2. TRAVEL MONITORING SYSTEM
#    When a SIM is registered as abroad → all outgoing transfers are blocked.
#    SIM is re-enabled only when user confirms return.
# ─────────────────────────────────────────────────────────────────────────────
class TravelMonitoringSystem:
    def __init__(self, user_system: UserRegistrationSystem):
        self.user_system = user_system

    @property
    def db_config(self):
        return self.user_system.db_config
    
    def get_connection(self):
        """Create and return a PostgreSQL database connection."""
        return psycopg2.connect(**self.db_config)

    def register_travel(self, phone_number: str, departure_date: str,
                        return_date: str, destination_country: str) -> dict:
        """
        Service provider registers that this SIM holder is leaving the country.
        Money transfers are immediately blocked.
        FIX: Block duplicate registrations.
        """
        conn = self.get_connection()
        c = conn.cursor()
        try:
            # Block duplicate: reject if already has an active (sim_deactivated=1) record
            c.execute('''
                SELECT id, destination_country, return_date FROM travel_records
                WHERE user_phone = %s AND sim_deactivated = TRUE
                ORDER BY id DESC LIMIT 1
            ''', (phone_number,))
            existing = c.fetchone()
            if existing:
                return {
                    "success": False,
                    "error": (f"This number already has an active travel record "
                              f"to {existing[1]} until {existing[2]}. "
                              f"Please reactivate the SIM before registering a new trip.")
                }
            c.execute('''
                INSERT INTO travel_records
                (user_phone, departure_date, return_date, destination_country, sim_deactivated)
                VALUES (%s, %s, %s, %s, TRUE)
            ''', (phone_number, departure_date, return_date, destination_country))
            c.execute("UPDATE users SET is_active = FALSE WHERE phone_number = %s",
                      (phone_number,))
            conn.commit()
            return {
                "success": True,
                "message": (f"Travel registered. Money transfers blocked for "
                            f"{phone_number} until {return_date}. "
                            f"Destination: {destination_country}.")
            }
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def reactivate_on_return(self, phone_number: str) -> dict:
        """Re-enable transfers after user confirms return.
        FIX: Find the latest record regardless of date, mark sim_deactivated=0,
        set return_date to yesterday so is_user_abroad() returns False immediately.
        """
        conn = self.get_connection()
        c = conn.cursor()
        try:
            # Get the latest travel record for this phone
            c.execute('''
                SELECT id FROM travel_records
                WHERE user_phone = %s
                ORDER BY id DESC LIMIT 1
            ''', (phone_number,))
            row = c.fetchone()
            if row:
                # Set return_date to yesterday so is_user_abroad() is False immediately
                yesterday = (datetime.now() - __import__('datetime').timedelta(days=1)).strftime('%Y-%m-%d')
                c.execute('''
                    UPDATE travel_records
                    SET sim_deactivated = FALSE, return_date = %s
                    WHERE id = %s
                ''', (yesterday, row[0]))
                c.execute("UPDATE users SET is_active = TRUE WHERE phone_number = %s",
                          (phone_number,))
                conn.commit()
                return {"success": True,
                        "message": "SIM reactivated. Transfers enabled."}
            return {"success": False,
                    "error": "No travel record found for this user."}
        except Exception as e:
            return {"success": False, "error": str(e)}
        finally:
            conn.close()

    def is_user_abroad(self, phone_number: str) -> bool:
        """Return True only if travel record is active AND sim is still deactivated.
        FIX: Use date() comparison and also check sim_deactivated=1.
        """
        conn = self.get_connection()
        c = conn.cursor()
        today = datetime.now().strftime('%Y-%m-%d')
        c.execute('''
            SELECT id FROM travel_records
            WHERE user_phone = %s
              AND date(departure_date) <= date(%s)
              AND date(return_date)    >= date(%s)
              AND sim_deactivated = TRUE
        ''', (phone_number, today, today))
        row = c.fetchone()
        conn.close()
        return row is not None

    def get_travel_status(self, phone_number: str) -> dict:
        """FIX: Return is_abroad key (frontend expects this), query only active records."""
        conn = self.get_connection()
        c = conn.cursor()
        # Only get records where sim is still deactivated (not yet reactivated)
        c.execute('''
            SELECT departure_date, return_date, destination_country, sim_deactivated
            FROM travel_records
            WHERE user_phone = %s AND sim_deactivated = TRUE
            ORDER BY id DESC LIMIT 1
        ''', (phone_number,))
        row = c.fetchone()
        conn.close()
        if not row:
            return {
                "has_travel_record": False,
                "is_abroad": False,
            }
        is_abroad = self.is_user_abroad(phone_number)
        return {
            "has_travel_record"  : True,
            "departure_date"     : row[0],
            "return_date"        : row[1],
            "destination_country": row[2],
            "sim_deactivated"    : bool(row[3]),
            "is_abroad"          : is_abroad,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 3. TRANSACTION ANOMALY DETECTOR  (rule-based, complements ML model)
# ─────────────────────────────────────────────────────────────────────────────
class TransactionAnomalyDetector:
    ANOMALY_THRESHOLD = 0.65   # above this → face verification required

    def __init__(self, user_system: UserRegistrationSystem):
        self.user_system = user_system

    @property
    def db_config(self):
        return self.user_system.db_config
    
    def get_connection(self):
        """Create and return a PostgreSQL database connection."""
        return psycopg2.connect(**self.db_config)

    def record_transaction(self, phone_number: str, amount: float,
                           transaction_type: str,
                           recipient_phone: str = None) -> dict:
        """Record transaction and return rule-based anomaly score."""
        conn = self.get_connection()
        c = conn.cursor()
        try:
            c.execute('''
                SELECT amount, timestamp FROM transaction_history
                WHERE user_phone = %s
                ORDER BY timestamp DESC LIMIT 50
            ''', (phone_number,))
            history = c.fetchall()

            score = self._calculate_anomaly_score(amount, history)
            is_anomalous = score >= self.ANOMALY_THRESHOLD

            c.execute('''
                INSERT INTO transaction_history
                (user_phone, amount, transaction_type, recipient_phone, fraud_score)
                VALUES (%s, %s, %s, %s, %s)
            ''', (phone_number, amount, transaction_type, recipient_phone, score))
            conn.commit()

            return {
                "anomaly_score"          : round(score, 4),
                "is_anomalous"           : is_anomalous,
                "requires_verification"  : is_anomalous,
                "message"                : ("Unusual transaction pattern detected — "
                                            "face verification required."
                                            if is_anomalous else "Normal transaction pattern.")
            }
        except Exception as e:
            return {"anomaly_score": 0.5, "is_anomalous": False,
                    "requires_verification": False, "error": str(e)}
        finally:
            conn.close()

    def _calculate_anomaly_score(self, amount: float, history: list) -> float:
        if not history:
            return 0.4   # first transaction: slight caution

        amounts = [h[0] for h in history]
        mean_amt = np.mean(amounts)
        std_amt  = np.std(amounts)

        # Z-score component
        z = abs(amount - mean_amt) / std_amt if std_amt > 0 else 0
        score = min(z / 3.0, 1.0)

        # Large amount bonus
        if mean_amt > 0 and amount > mean_amt * 8:
            score = min(score + 0.25, 1.0)

        # Round-number pattern (large multiples of 50k)
        if amount >= 50_000 and amount % 50_000 == 0:
            score = min(score + 0.10, 1.0)

        # Very late-night transaction (midnight–4am)
        hour = datetime.now().hour
        if hour < 4 or hour >= 23:
            score = min(score + 0.10, 1.0)

        return score

    def get_user_transaction_pattern(self, phone_number: str, days: int = 30) -> dict | None:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT amount, transaction_type, timestamp
            FROM transaction_history
            WHERE user_phone = %s
              AND timestamp >= NOW() - INTERVAL '1 day' * %s
            ORDER BY timestamp
        ''', (phone_number, days))
        rows = c.fetchall()
        conn.close()
        if not rows:
            return None
        df = pd.DataFrame(rows, columns=["amount", "type", "timestamp"])
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return {
            "avg_amount"       : df["amount"].mean(),
            "max_amount"       : df["amount"].max(),
            "min_amount"       : df["amount"].min(),
            "transaction_count": len(df),
            "daily_avg"        : df.groupby(df["timestamp"].dt.date).size().mean(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 4. PIN MONITORING SYSTEM
# ─────────────────────────────────────────────────────────────────────────────
class PinMonitoringSystem:
    def __init__(self, user_system: UserRegistrationSystem):
        self.user_system = user_system

    @property
    def db_config(self):
        return self.user_system.db_config
    
    def get_connection(self):
        """Create and return a PostgreSQL database connection."""
        return psycopg2.connect(**self.db_config)

    def record_pin_attempt(self, phone_number: str, was_successful: bool,
                           ip_address: str = None, device_id: str = None) -> dict:
        conn = self.get_connection()
        c = conn.cursor()
        try:
            c.execute('''
                INSERT INTO pin_attempts (user_phone, was_successful, ip_address, device_id)
                VALUES (%s, %s, %s, %s)
            ''', (phone_number, was_successful, ip_address, device_id))
            suspicious = self._check_suspicious(phone_number, c)
            conn.commit()
            return suspicious
        except Exception as e:
            return {"requires_verification": True, "risk_level": "error", "error": str(e)}
        finally:
            conn.close()

    def _check_suspicious(self, phone_number: str, cursor) -> dict:
        cursor.execute('''
            SELECT COUNT(*) FROM pin_attempts
            WHERE user_phone = %s AND was_successful = FALSE
              AND attempt_time >= NOW() - INTERVAL '5 minutes'
        ''', (phone_number,))
        recent_fail = cursor.fetchone()[0]

        cursor.execute('''
            SELECT COUNT(*) FROM pin_attempts
            WHERE user_phone = %s AND was_successful = FALSE
              AND attempt_time >= NOW() - INTERVAL '1 hour'
        ''', (phone_number,))
        hour_fail = cursor.fetchone()[0]

        if recent_fail >= 2:
            return {"requires_verification": True, "risk_level": "high",
                    "message": "Multiple rapid PIN failures — possible SIM theft."}
        elif hour_fail >= 3:
            return {"requires_verification": True, "risk_level": "medium",
                    "message": "Repeated PIN failures in last hour."}
        return {"requires_verification": False, "risk_level": "low",
                "message": "Normal PIN activity."}

    def get_pin_security_status(self, phone_number: str) -> dict:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT was_successful, attempt_time
            FROM pin_attempts
            WHERE user_phone = %s
            ORDER BY attempt_time DESC LIMIT 10
        ''', (phone_number,))
        rows = c.fetchall()
        conn.close()

        failed = sum(1 for r in rows if not r[0])
        score  = max(100 - failed * 15, 0)
        if rows and failed / len(rows) > 0.5:
            score = max(score - 20, 0)

        return {
            "recent_attempts": len(rows),
            "failed_attempts": failed,
            "last_attempt"   : rows[0][1] if rows else None,
            "security_score" : score,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 5. FRAUD ALERT SYSTEM  (notifies service provider in real time)
# ─────────────────────────────────────────────────────────────────────────────
class FraudAlertSystem:
    """
    Sends structured alerts to the service provider dashboard whenever
    the ML model or rule engine flags a suspicious transaction.

    In production this would POST to an SMS gateway or push-notification
    service.  For now alerts are logged to the database and returned in
    the API response so the dashboard can display them.
    """

    def __init__(self, db_config):
        self.db_config = db_config
        self._ensure_table()
    
    def get_connection(self):
        """Create and return a PostgreSQL database connection."""
        return psycopg2.connect(**self.db_config)

    def _ensure_table(self):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS fraud_alerts (
                id             SERIAL PRIMARY KEY,
                phone_number   TEXT,
                amount         REAL,
                fraud_score    REAL,
                risk_level     TEXT,
                action         TEXT,
                alert_message  TEXT,
                created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                acknowledged   BOOLEAN DEFAULT FALSE
            )
        ''')
        conn.commit()
        c.close()
        conn.close()

    def raise_alert(self, phone_number: str, amount: float,
                    fraud_score: float, risk_level: str,
                    action: str, extra_info: str = "") -> dict:
        """Log a fraud alert and return the alert record."""
        msg = (
            f"[FRAUD ALERT] Phone: {phone_number} | "
            f"Amount: {amount:,.0f} RWF | Score: {fraud_score:.3f} | "
            f"Risk: {risk_level} | Action: {action}. {extra_info}"
        )
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            INSERT INTO fraud_alerts
            (phone_number, amount, fraud_score, risk_level, action, alert_message)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        ''', (phone_number, amount, fraud_score, risk_level, action, msg))
        alert_id = c.fetchone()[0]
        conn.commit()
        c.close()
        conn.close()

        print(f"\n🚨 {msg}\n")
        return {"alert_id": alert_id, "message": msg, "timestamp": datetime.now().isoformat()}

    def get_unacknowledged_alerts(self) -> list:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, phone_number, amount, fraud_score, risk_level,
                   action, alert_message, created_at
            FROM fraud_alerts WHERE acknowledged = FALSE
            ORDER BY created_at DESC
        ''')
        rows = c.fetchall()
        c.close()
        conn.close()
        return [
            {"id": r[0], "phone": r[1], "amount": r[2], "fraud_score": r[3],
             "risk_level": r[4], "action": r[5], "message": r[6], "created_at": r[7]}
            for r in rows
        ]

    def acknowledge_alert(self, alert_id: int) -> dict:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("UPDATE fraud_alerts SET acknowledged = TRUE WHERE id = %s", (alert_id,))
        conn.commit()
        c.close()
        conn.close()
        return {"success": True, "alert_id": alert_id}

    def update_alert(self, alert_id: int, new_action: str, extra_info: str) -> dict:
        """Update an existing alert's action and message (e.g. REQUIRE_FACE → BLOCK after face fail)."""
        conn = self.get_connection()
        c = conn.cursor()
        # Get existing message and update it
        c.execute("SELECT alert_message, phone_number, amount, fraud_score, risk_level FROM fraud_alerts WHERE id=%s",
                  (alert_id,))
        row = c.fetchone()
        if row:
            orig_msg, phone, amount, score, risk = row
            # Rebuild message with updated action and appended extra_info
            new_msg = orig_msg.replace(f"Action: {orig_msg.split('Action: ')[-1].split('.')[0]}",
                                       f"Action: {new_action}")
            if extra_info and extra_info not in new_msg:
                new_msg = new_msg.rstrip('. ') + f". {extra_info}"
            c.execute(
                "UPDATE fraud_alerts SET action=%s, alert_message=%s, risk_level='HIGH' WHERE id=%s",
                (new_action, new_msg, alert_id)
            )
        conn.commit()
        conn.close()
        return {"success": True, "alert_id": alert_id}


def _build_fraud_reason(phone_number: str, amount: float, ml_score: float,
                         db_config: dict) -> str:
    """
    Used in fraud_alerts.alert_message so admin can understand what happened.
    """
    try:
        conn = psycopg2.connect(**db_config)
        c = conn.cursor()

        # Get sender balance
        c.execute("SELECT account_balance FROM users WHERE phone_number=%s", (phone_number,))
        row = c.fetchone()
        balance = row[0] if row else 0.0

        # Rapid transfers in last 60 seconds
        c.execute("""
            SELECT COUNT(*) FROM transaction_history
            WHERE user_phone = %s
              AND timestamp >= NOW() - INTERVAL '60 seconds'
        """, (phone_number,))
        rapid = c.fetchone()[0] or 0

        # Rapid transfers in last 5 minutes
        c.execute("""
            SELECT COUNT(*) FROM transaction_history
            WHERE user_phone = %s
              AND timestamp >= NOW() - INTERVAL '5 minutes'
        """, (phone_number,))
        rapid_5m = c.fetchone()[0] or 0
        conn.close()

        reasons = []

        if balance > 0:
            ratio = amount / balance
            if ratio >= 2.0:
                reasons.append(f"Amount is {ratio:.1f}x above balance ({balance:,.0f} RWF) — extreme overspend")
            elif ratio >= 1.0:
                reasons.append(f"Amount ({amount:,.0f} RWF) exceeds balance ({balance:,.0f} RWF) — insufficient funds attempted twice")
            elif ratio >= 0.95:
                reasons.append(f"Amount drains nearly full balance ({balance:,.0f} RWF) — drain pattern")
        elif amount > 0:
            reasons.append(f"Amount {amount:,.0f} RWF attempted with zero balance")

        if rapid >= 5:
            reasons.append(f"{rapid} rapid transfers in last 60 seconds — velocity fraud")
        elif rapid >= 3:
            reasons.append(f"{rapid} transfers in last 60 seconds — suspicious frequency")
        elif rapid_5m >= 8:
            reasons.append(f"{rapid_5m} transfers in last 5 minutes — high frequency")

        if not reasons:
            reasons.append(f"ML model flagged transaction (score={ml_score:.3f})")

        return " | ".join(reasons)

    except Exception as e:
        return f"ML fraud score={ml_score:.3f}"


# ─────────────────────────────────────────────────────────────────────────────
# 6. REAL-TIME FRAUD DETECTOR  (main engine, used by money_transfer.py)
# ─────────────────────────────────────────────────────────────────────────────
class RealTimeFraudDetector:
    """
    Pipeline:
      1. Check user is active (not abroad, not locked)
      2. ML model score ONLY (trained in Momo_Clean.ipynb, saved as .pkl)
         — fraud decision comes entirely from the trained model, no hand-written rules
      3. If HIGH risk  → block + raise alert + require face verification
         If MEDIUM     → require face verification before proceeding
         If LOW        → allow

    NOTE: Rule-based anomaly scoring and PIN-risk weighting are intentionally
    NOT used in the fraud decision. The ML model is the sole judge.
    TransactionAnomalyDetector.record_transaction() is still called to LOG
    the transaction to transaction_history (needed for ML feature building),
    but its anomaly_score does NOT influence the fraud decision — the ML model is the sole judge.
    """

    # Risk thresholds (combined score 0–1)
    HIGH_RISK_THRESHOLD   = 0.65
    MEDIUM_RISK_THRESHOLD = 0.40

    def __init__(self, db_config):
        self.db_config = db_config
        self.user_reg = UserRegistrationSystem(db_config)
        self.travel_sys = TravelMonitoringSystem(self.user_reg)
        self.anomaly_det = TransactionAnomalyDetector(self.user_reg)
        self.pin_monitor = PinMonitoringSystem(self.user_reg)
        self.alert_sys = FraudAlertSystem(db_config)
        self._load_ml_model()
    
    def get_connection(self):
        """Create and return a PostgreSQL database connection."""
        return psycopg2.connect(**self.db_config)

    def _load_ml_model(self):
        try:
            self.model  = joblib.load("fraud_best_model.pkl")
            self.scaler = joblib.load("fraud_scaler.pkl")
            with open("fraud_config.json") as f:
                self.config = json.load(f)
            self.threshold = self.config.get("threshold", 0.5)
            print(f"[FraudDetector] ML model loaded: {self.config.get('best_model')} "
                  f"| threshold={self.threshold}")
        except FileNotFoundError:
            print("[FraudDetector] ML model not found — using rule-based detection only. "
                  "Run Momo_Clean.ipynb to train and save the model.")
        except Exception as e:
            print(f"[FraudDetector] Error loading model: {e}")

    # ── Feature builder ───────────────────────────────────────────────────

    def _build_ml_features(self, phone_number: str, amount: float,
                            network: str) -> list:
        """
        Build the 14-feature vector that matches Momo_Clean.ipynb FEATURES list.
        Uses live balance from DB + transaction history.
        """
        # Get live balance
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT account_balance FROM users WHERE phone_number = %s",
                  (phone_number,))
        row = c.fetchone()
        conn.close()
        old_balance = row[0] if row else 0.0
        new_balance = max(old_balance - amount, 0.0)

        # Historical pattern
        pattern = self.anomaly_det.get_user_transaction_pattern(phone_number)
        avg_amount  = pattern["avg_amount"] if pattern else amount
        tx_count    = pattern["transaction_count"] if pattern else 0

        # Derived features
        log_amount          = np.log1p(amount)
        log_old_orig        = np.log1p(old_balance)
        log_new_orig        = np.log1p(new_balance)
        log_old_dest        = 0.0           # recipient balance unknown
        log_new_dest        = log_amount    # approximate
        orig_balance_drop   = log_old_orig - log_new_orig
        dest_balance_gain   = log_new_dest - log_old_dest
        balance_mismatch    = orig_balance_drop - dest_balance_gain
        sender_zero_after   = int(new_balance == 0)
        dest_zero_before    = 0             # unknown
        amount_to_bal_ratio = amount / (old_balance + 1)

        # Encode transaction type: TRANSFER=4, CASH_OUT=1 (PaySim encoding)
        type_map = {"MTN": 4, "Tigo": 4}   # mobile transfers → TRANSFER
        type_encoded = type_map.get(network, 4)

        hour_of_day    = datetime.now().hour
        is_high_amount = int(amount > 100_000)

        # NEW features — learned by ML model
        amount_exceeds_balance = int(amount > old_balance)
        excess_ratio           = min(amount / (old_balance + 1), 10)

        # Rapid transfer count: how many transfers in last 60 seconds
        conn2 = self.get_connection()
        c2    = conn2.cursor()
        c2.execute("""
            SELECT COUNT(*) FROM transaction_history
            WHERE user_phone = %s
              AND timestamp >= NOW() - INTERVAL '60 seconds'
        """, (phone_number,))
        rapid_tx_count = c2.fetchone()[0]
        c2.close()
        conn2.close()

        return [
            log_amount, log_old_orig, log_new_orig,
            log_old_dest, log_new_dest,
            orig_balance_drop, dest_balance_gain, balance_mismatch,
            sender_zero_after, dest_zero_before, amount_to_bal_ratio,
            type_encoded, hour_of_day, is_high_amount,
            amount_exceeds_balance, excess_ratio, rapid_tx_count,
        ]

    # ── ML scoring ────────────────────────────────────────────────────────

    def ml_score(self, phone_number: str, amount: float, network: str) -> float:
        """Return ML fraud probability (0–1). Falls back to 0.5 on error."""
        if not self.model or not self.scaler:
            return 0.5
        try:
            features = self._build_ml_features(phone_number, amount, network)
            vec      = np.array([features])
            vec_s    = self.scaler.transform(vec)
            return float(self.model.predict_proba(vec_s)[0][1])
        except Exception as e:
            print(f"[MLScore] Error: {e}")
            return 0.5

    # ── Main check ────────────────────────────────────────────────────────

    def evaluate_transaction(self, phone_number: str, amount: float,
                             recipient_phone: str, network: str,
                             face_base64: str = None,
                             untrusted: bool = False) -> dict:
        """
        Full fraud pipeline.  Called by money_transfer.py BEFORE deducting
        balance.  Returns:
          {
            "action"        : "ALLOW" | "REQUIRE_FACE" | "BLOCK",
            "risk_level"    : "LOW"   | "MEDIUM"       | "HIGH",
            "fraud_score"   : float,  # combined 0–1
            "ml_score"      : float,
            "rule_score"    : float,
            "face_verified" : bool | None,
            "alert"         : dict | None,
            "message"       : str,
            "checks"        : dict,   # per-check detail
          }

        untrusted=True is set by money_transfer.py when the user previously
        attempted a transfer that exceeded their balance but now the amount
        fits.  This forces face verification regardless of ML score.
        """
        checks = {}
        result = {
            "action"       : "ALLOW",
            "risk_level"   : "LOW",
            "fraud_score"  : 0.0,
            "ml_score"     : 0.0,
            "rule_score"   : 0.0,
            "face_verified": None,
            "alert"        : None,
            "message"      : "",
            "checks"       : checks,
        }

        # ── 1. User active%s ───────────────────────────────────────────────
        user = self.user_reg.get_user_info(phone_number)
        if not user:
            checks["user"] = {"passed": False, "msg": "User not found"}
            result.update({"action": "BLOCK", "risk_level": "HIGH",
                           "message": "User not found."})
            return result
        if not user["is_active"]:
            checks["user"] = {"passed": False, "msg": "Account inactive"}
            result.update({"action": "BLOCK", "risk_level": "HIGH",
                           "message": "Account is inactive. If you are abroad, "
                                      "please contact your service provider to reactivate."})
            return result
        checks["user"] = {"passed": True, "msg": f"Active user: {user['full_name']}"}

        # ── 2. ML is the sole judge — no hard balance-multiplier rule ────
        #   The model was trained on excess_ratio and amount_exceeds_balance
        #   features, so 2x / 3x above balance is detected by ML alone.
        checks["balance_multiplier"] = {"passed": True, "msg": "Delegated to ML model"}

        # ── 3. Travel check ───────────────────────────────────────────────
        # Travel blocking is now handled in money_transfer.py before this
        # function is called (abroad users go through email face-verify flow).
        # No hard block here.
        checks["travel"] = {"passed": True, "msg": "Travel handled upstream"}

        # ── 4. Log transaction to history (needed for ML feature building) ──
        #   record_transaction() writes to transaction_history so that
        #   _build_ml_features() can compute avg_amount / tx_count.
        #   Its anomaly_score is captured for transparency but does NOT
        #   influence the fraud decision — the ML model is the sole judge.
        anomaly = self.anomaly_det.record_transaction(
            phone_number, amount, "TRANSFER", recipient_phone)
        checks["transaction_logged"] = {
            "passed": True,
            "msg"   : "Transaction recorded for ML feature history."
        }

        # ── 5. ML model score — SOLE fraud decision ───────────────────────
        ml_s = self.ml_score(phone_number, amount, network)
        checks["ml_model"] = {
            "score"    : round(ml_s, 4),
            "threshold": self.threshold,
            "msg"      : f"ML fraud probability: {ml_s:.4f}"
        }

        # ── 6. Fraud score = ML score only ────────────────────────────────
        combined = round(ml_s, 4)

        result["fraud_score"] = combined
        result["ml_score"]    = round(ml_s, 4)
        result["rule_score"]  = 0.0   # not used in decision

        # ── 7. Risk classification (based on ML score only) ──────────────
        if combined >= self.HIGH_RISK_THRESHOLD:
            result["risk_level"] = "HIGH"
        elif combined >= self.MEDIUM_RISK_THRESHOLD:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "LOW"

        # ── 7b. Untrusted user override ───────────────────────────────────
        # If money_transfer.py flagged this user as untrusted (they previously
        # attempted a transfer that exceeded their balance), force face
        # verification even if the ML score would normally ALLOW the transaction.
        if untrusted and result["risk_level"] == "LOW":
            result["risk_level"] = "MEDIUM"   # elevate so face gate triggers
            checks["untrusted_override"] = {
                "active": True,
                "msg": (
                    "User previously attempted a transfer exceeding their balance. "
                    "Face verification required for next transaction."
                )
            }

        # ── 8. Face verification gate ─────────────────────────────────────
        if result["risk_level"] in ("HIGH", "MEDIUM"):
            if face_base64:
                # User has provided face image — verify it
                face_result = self.user_reg.verify_face_from_base64(
                    phone_number, face_base64)
                result["face_verified"] = face_result.get("verified", False)
                checks["face"] = face_result

                if result["face_verified"]:
                    # Face match = identity confirmed = ALLOW always.
                    # The face is the ultimate proof of identity. If the person
                    # in front of the camera matches the registered face, we trust
                    # them regardless of ML score, velocity, or risk level.
                    # Velocity and ML signals only block when we CANNOT confirm
                    # who is making the transaction. Face mismatch keeps full
                    # blocking (see else branch below).
                    extra = (
                        " Your previous over-balance attempt has been cleared."
                        if untrusted else ""
                    )
                    result["risk_level"] = "LOW"
                    result["action"]     = "ALLOW"
                    result["message"]    = f"Face verification passed. Transaction approved.{extra}"
                else:
                    # Face failed
                    result["action"]  = "BLOCK"
                    result["message"] = ("Face verification failed. "
                                         "Transaction blocked for your security.")
                    # Close the pending REQUIRE_FACE alert and update it instead of creating a new one
                    pending_id = result.get("_alert_id")
                    if pending_id:
                        self.alert_sys.update_alert(pending_id, "BLOCK",
                            "Face verification failed — identity could not be confirmed.")
                    else:
                        reason = _build_fraud_reason(phone_number, amount, ml_s, self.db_config)
                        result["alert"] = self.alert_sys.raise_alert(
                            phone_number, amount, combined,
                            "HIGH", "BLOCK",
                            f"{reason}. Face verification failed — identity not confirmed.")
                    result["face_failed"] = True
            else:
                # No face provided yet — ask for it
                if untrusted and result["risk_level"] == "MEDIUM":
                    face_msg = (
                        "A previous transfer attempt exceeded your account balance. "
                        "For your security, please verify your face to continue."
                    )
                elif result["risk_level"] == "MEDIUM":
                    face_msg = (
                        "Unusual activity detected on this transaction. "
                        "Please complete face verification to proceed."
                    )
                else:
                    face_msg = (
                        "High fraud risk detected. Face verification required before transfer."
                    )
                result["action"]  = "REQUIRE_FACE"
                result["message"] = face_msg
                # Raise a service-provider alert immediately
                # Build human-readable reason for admin
                reason = _build_fraud_reason(phone_number, amount, ml_s, self.db_config)
                result["alert"] = self.alert_sys.raise_alert(
                    phone_number, amount, combined,
                    result["risk_level"], "REQUIRE_FACE",
                    reason)
                result["_alert_id"] = result["alert"].get("alert_id") if result["alert"] else None
        else:
            result["action"]  = "ALLOW"
            result["message"] = "Transaction approved."

        return result

    # ── Convenience wrappers ──────────────────────────────────────────────

    def get_fraud_alerts(self) -> list:
        """Return all unacknowledged alerts (for admin dashboard)."""
        return self.alert_sys.get_unacknowledged_alerts()

    def acknowledge_alert(self, alert_id: int) -> dict:
        return self.alert_sys.acknowledge_alert(alert_id)
