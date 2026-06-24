"""
money_transfer.py — Money Transfer System
==========================================
Flow:
  1. Validate session → get sender
  2. Validate recipient phone → detect network (MTN / Tigo)
  3. Validate amount (> 0 only)
  4. Run RealTimeFraudDetector.evaluate_transaction()   ← ML runs FIRST
       - ALLOW          → check balance, deduct, complete transfer
       - REQUIRE_FACE   → return face-verification challenge to frontend
       - BLOCK          → reject immediately (ML caught it — above balance,
                          drain, rapid transfers, etc.)
  5. Balance check ONLY happens after ML says ALLOW
  6. If caller supplies face_base64 on retry → fraud check runs again
     with the image, resolves to ALLOW or BLOCK
"""

import psycopg2
import psycopg2.extras
import re
import random
from datetime import datetime
from auth_system import AuthenticationSystem
from fraud_detection import RealTimeFraudDetector


class MoneyTransferSystem:
    def __init__(self, db_config):
        self.db_config  = db_config
        self.auth       = AuthenticationSystem(db_config)
        self.fraud_det  = RealTimeFraudDetector(db_config)
        self._init_tables()
        self._init_abroad_pending_table()
        self._init_balance_attempt_table()
    
    def get_connection(self):
        """Create and return a PostgreSQL database connection."""
        return psycopg2.connect(**self.db_config)

    # ─────────────────────────────────────────────────────────────────────
    # DATABASE INIT
    # ─────────────────────────────────────────────────────────────────────

    def _init_tables(self):
        conn = self.get_connection()
        c = conn.cursor()

        c.execute('''
            CREATE TABLE IF NOT EXISTS money_transfers (
                id               SERIAL PRIMARY KEY,
                sender_id        INTEGER NOT NULL,
                recipient_phone  TEXT    NOT NULL,
                amount           REAL    NOT NULL,
                fee              REAL    DEFAULT 0.0,
                transfer_type    TEXT    NOT NULL,
                network          TEXT    NOT NULL,
                reference_number TEXT    UNIQUE,
                status           TEXT    DEFAULT 'pending',
                fraud_score      REAL    DEFAULT 0.0,
                ml_score         REAL    DEFAULT 0.0,
                rule_score       REAL    DEFAULT 0.0,
                risk_level       TEXT    DEFAULT 'LOW',
                is_fraud         BOOLEAN DEFAULT FALSE,
                face_verified    BOOLEAN DEFAULT FALSE,
                created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at     TIMESTAMP,
                notes            TEXT,
                FOREIGN KEY (sender_id) REFERENCES users (id)
            )
        ''')

        c.execute('''
            CREATE TABLE IF NOT EXISTS network_fees (
                id             SERIAL PRIMARY KEY,
                network        TEXT NOT NULL,
                min_amount     REAL DEFAULT 0,
                max_amount     REAL DEFAULT 999999999,
                fee_type       TEXT DEFAULT 'fixed',
                fee_amount     REAL DEFAULT 0,
                percentage_fee REAL DEFAULT 0
            )
        ''')

        # Seed fees once
        c.execute("DELETE FROM network_fees")
        c.execute("SELECT COUNT(*) FROM network_fees")
        if c.fetchone()[0] == 0:
            c.executemany('''
                INSERT INTO network_fees
                (network, min_amount, max_amount, fee_type, fee_amount, percentage_fee)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', [
                ("MTN",  1,        1000,       "fixed",      20,   0.0),
                ("MTN",  1001,     10000,      "fixed",     100,   0.0),
                ("MTN",  10001,    150000,     "fixed",     250,   0.0),
                ("MTN",  150001,   2000000,    "fixed",    1500,   0.0),
                ("Tigo", 1,        1000,       "fixed",      20,   0.0),
                ("Tigo", 1001,     10000,      "fixed",     100,   0.0),
                ("Tigo", 10001,    150000,     "fixed",     250,   0.0),
                ("Tigo", 150001,   2000000,    "fixed",    1500,   0.0),
            ])

        try:
            c.execute('ALTER TABLE money_transfers ADD COLUMN IF NOT EXISTS fee REAL DEFAULT 0.0')
            conn.commit()
        except Exception:
            pass
        conn.commit()
        c.close()
        conn.close()

    # ─────────────────────────────────────────────────────────────────────
    # OVER-BALANCE ATTEMPT TRACKING
    # ─────────────────────────────────────────────────────────────────────

    def _init_abroad_pending_table(self):
        """Table for transfers that need abroad-owner face verification via email link."""
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS abroad_pending_transfers (
                id               SERIAL PRIMARY KEY,
                sender_id        INTEGER NOT NULL,
                recipient_phone  TEXT    NOT NULL,
                amount           REAL    NOT NULL,
                fee              REAL    DEFAULT 0.0,
                transfer_type    TEXT    NOT NULL,
                network          TEXT    NOT NULL,
                verify_token     TEXT    UNIQUE NOT NULL,
                status           TEXT    DEFAULT 'pending',
                destination      TEXT,
                expires_at       TIMESTAMP NOT NULL,
                created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
        conn.close()

    def _init_balance_attempt_table(self):
        """
        Tracks consecutive over-balance attempts per user.
        Resets when a transaction is eventually allowed or when the user
        makes a successful transfer.
        """
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS over_balance_attempts (
                user_id       INTEGER PRIMARY KEY,
                attempt_count INTEGER DEFAULT 0,
                last_attempt  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
        conn.close()

    def _get_over_balance_count(self, user_id: int) -> int:
        conn = self.get_connection()
        c = conn.cursor()
        
        # Check if last attempt was from a previous day - if so, reset at midnight
        c.execute(
            "SELECT attempt_count, last_attempt FROM over_balance_attempts WHERE user_id = %s",
            (user_id,)
        )
        row = c.fetchone()
        
        if row:
            attempt_count, last_attempt = row
            # Convert last_attempt to date and compare with today
            from datetime import datetime
            last_date = last_attempt.date() if hasattr(last_attempt, 'date') else datetime.strptime(str(last_attempt)[:19], "%Y-%m-%d %H:%M:%S").date()
            today = datetime.now().date()
            
            if last_date < today:
                # Reset counter at midnight for new day
                c.execute(
                    "DELETE FROM over_balance_attempts WHERE user_id = %s",
                    (user_id,)
                )
                conn.commit()
                conn.close()
                return 0
            else:
                conn.close()
                return attempt_count
        else:
            conn.close()
            return 0

    def _increment_over_balance(self, user_id: int):
      conn = self.get_connection()
      c = conn.cursor()
      c.execute('''
        INSERT INTO over_balance_attempts (user_id, attempt_count, last_attempt)
        VALUES (%s, 1, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE
        SET attempt_count = over_balance_attempts.attempt_count + 1,
            last_attempt  = CURRENT_TIMESTAMP
      ''', (user_id,))
      conn.commit()
      conn.close()

    def _reset_over_balance(self, user_id: int):
        conn = self.get_connection()
        c = conn.cursor()
        c.execute(
            "DELETE FROM over_balance_attempts WHERE user_id = %s",
            (user_id,)
        )
        conn.commit()
        conn.close()

    # ─────────────────────────────────────────────────────────────────────
    # HELPERS
    # ─────────────────────────────────────────────────────────────────────

    def _validate_recipient(self, phone: str) -> dict:
        phone = phone.strip().replace(" ", "")
        if phone.startswith("+250"):
            core = phone[4:]
        elif phone.startswith("250"):
            core = phone[3:]
        elif phone.startswith("0"):
            core = phone[1:]
        else:
            core = phone

        if re.match(r'^(78|79)\d{7}$', core):
            return {"valid": True,  "phone": f"+250{core}", "network": "MTN"}
        if re.match(r'^(72|73)\d{7}$', core):
            return {"valid": True,  "phone": f"+250{core}", "network": "Tigo"}
        return {"valid": False, "phone": phone, "network": None}

    def _calculate_fee(self, network: str, amount: float) -> float:
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT fee_type, fee_amount, percentage_fee
            FROM network_fees
            WHERE network=%s AND min_amount<=%s AND max_amount>=%s
        ''', (network, amount, amount))
        row = c.fetchone()
        conn.close()
        if not row:
            return 0.0
        fee_type, fee_amount, pct = row
        return fee_amount if fee_type == "fixed" else (amount * pct / 100)

    def _generate_reference(self) -> str:
        return f"TXN{datetime.now().strftime('%Y%m%d')}{random.randint(100000,999999)}"

    def _get_balance(self, user_id: int) -> float:
        return self.auth.get_user_balance(user_id)

    # ─────────────────────────────────────────────────────────────────────
    # MAIN TRANSFER METHOD
    # ─────────────────────────────────────────────────────────────────────

    def initiate_transfer(self, session_token: str,
                          recipient_phone: str,
                          amount: float,
                          transfer_type: str = "mobile_money",
                          face_base64: str = None) -> dict:

        # ── 1. Session validation ────────────────────────────────────────
        user = self.auth.validate_session(session_token)
        if not user:
            return {"success": False,
                    "error": "Session expired. Please log in again."}

        # ── 1b. Travel check (sender) — ALLOW but require owner email-face verify ──
        try:
            conn = self.get_connection()
            c = conn.cursor()
            today = __import__('datetime').date.today().isoformat()
            c.execute('''
                SELECT destination_country, return_date FROM travel_records
                WHERE user_phone = %s
                  AND date(departure_date) <= date(%s)
                  AND date(return_date)    >= date(%s)
                  AND sim_deactivated = TRUE
                ORDER BY id DESC LIMIT 1
            ''', (user["phone"], today, today))
            travel_row = c.fetchone()
            conn.close()
            if travel_row:
                # Sender is abroad — save as pending and email the owner for face verify
                return self._handle_abroad_transfer(
                    user, recipient_phone, amount, fee, transfer_type,
                    travel_row[0], str(travel_row[1])
                )
        except Exception:
            pass

        # ── 2. Recipient validation ───────────────────────────────────────
        recipient = self._validate_recipient(recipient_phone)
        if not recipient["valid"]:
            return {"success": False,
                    "error": ("Invalid recipient phone number. "
                              "Use 078, 079 (MTN) or 072, 073 (Tigo) format.")}

        # ── 2b. Recipient travel check — allow receiving while abroad ────────
        # Recipients can still receive money even if abroad; the sender-side
        # flow (handled above) is what gates the transaction via email verify.

        # ── 3. Basic input validation (not a rule — just math) ─────────────
        if not isinstance(amount, (int, float)) or amount <= 0:
            return {"success": False, "error": "Amount must be greater than 0."}

        fee   = self._calculate_fee(recipient["network"], amount)
        total = amount + fee

        # ── 3b. Over-balance attempt gating ──────────────────────────────
        # Rules (applied BEFORE ML to avoid unnecessary model call):
        #   1st attempt with amount > balance  → show "insufficient balance", done.
        #   2nd attempt:
        #     - amount still > balance          → hard block, no face needed.
        #     - amount now within balance       → mark user untrusted, pass to ML
        #                                         which will REQUIRE_FACE.
        #   Successful transfer resets counter.
        balance_now = self._get_balance(user["id"])
        over_balance_count = self._get_over_balance_count(user["id"])

        if amount > balance_now:
            if over_balance_count == 0:
                # First offence — soft message only, track it, return early.
                self._increment_over_balance(user["id"])
                return {
                    "success": False,
                    "error": (
                        f"Insufficient balance. "
                        f"You need {total:,.0f} RWF "
                        f"(amount {amount:,.0f} + fee {fee:,.0f}), "
                        f"but your balance is {balance_now:,.0f} RWF."
                    )
                }
            else:
                # Second (or more) offence and amount STILL over balance → hard block.
                self._increment_over_balance(user["id"])
                return {
                    "success": False,
                    "action": "BLOCK",
                    "error": (
                        "Transaction blocked. You have previously attempted a transfer "
                        "that exceeded your balance. Please top up your account and "
                        "contact support if you believe this is an error."
                    )
                }
        else:
            # Amount is within balance. Did the user PREVIOUSLY go over-balance?
            if over_balance_count > 0:
                # Previous attempt was over balance; amount now OK but user is untrusted.
                # Let ML handle it — pass `untrusted=True` so it forces REQUIRE_FACE
                # regardless of ML score.
                untrusted_flag = True
            else:
                untrusted_flag = False

        # ── 4. ML model — sole decision maker ────────────────────────────
        # No hard rules. The model decides everything: velocity bursts,
        # amount spikes, drain patterns — all learned from data.
        # Over-balance hard rules are handled above; untrusted flag forces face.
        fraud_result = self.fraud_det.evaluate_transaction(
            phone_number    = user["phone"],
            amount          = amount,
            recipient_phone = recipient["phone"],
            network         = recipient["network"],
            face_base64     = face_base64,
            untrusted       = untrusted_flag,
        )

        action        = fraud_result["action"]       # ALLOW | REQUIRE_FACE | BLOCK
        risk_level    = fraud_result["risk_level"]
        fraud_score   = fraud_result["fraud_score"]
        ml_score      = fraud_result["ml_score"]
        rule_score    = fraud_result["rule_score"]
        face_verified = fraud_result.get("face_verified")

        # ── 4a. Face verification required ───────────────────────────────
        if action == "REQUIRE_FACE":
            return {
                "success"      : False,
                "face_required": True,
                "action"       : "REQUIRE_FACE",
                "risk_level"   : risk_level,
                "fraud_score"  : fraud_score,
                "message"      : fraud_result["message"],
                "alert"        : fraud_result.get("alert"),
            }

        # ── 4b. Blocked by ML model ───────────────────────────────────────
        if action == "BLOCK":
            self._record_transfer(
                sender_id       = user["id"],
                recipient_phone = recipient["phone"],
                amount          = amount,
                transfer_type   = transfer_type,
                network         = recipient["network"],
                reference       = self._generate_reference(),
                status          = "blocked",
                fraud_score     = fraud_score,
                ml_score        = ml_score,
                rule_score      = rule_score,
                risk_level      = risk_level,
                is_fraud        = True,
                face_verified   = bool(face_verified) if face_verified is not None else False,
                fee             = fee,
                notes           = fraud_result["message"],
            )
            return {
                "success"    : False,
                "action"     : "BLOCK",
                "risk_level" : risk_level,
                "fraud_score": fraud_score,
                "error"      : fraud_result["message"],
                "alert"      : fraud_result.get("alert"),
            }

        # ── 5. Final balance check (safety net — ML should have caught issues above) ──
        balance = self._get_balance(user["id"])
        if balance < total:
            # Shouldn't reach here for 1x (handled before ML) or 2x+ (ML blocks)
            # This covers edge cases where ML allowed but balance is still short
            return {
                "success": False,
                "error": (
                    f"Insufficient balance. "
                    f"Required: {total:,.0f} RWF "
                    f"(amount {amount:,.0f} + fee {fee:,.0f}), "
                    f"available: {balance:,.0f} RWF."
                )
            }



        # ── 6. Complete the transfer ──────────────────────────────────────
        reference = self._generate_reference()

        conn = self.get_connection()
        c = conn.cursor()

        c.execute('''
            UPDATE users SET account_balance = account_balance - %s
            WHERE id = %s
        ''', (total, user["id"]))

        c.execute('''
            UPDATE users SET account_balance = account_balance + %s
            WHERE phone_number = %s AND is_active = TRUE
        ''', (amount, recipient["phone"]))

        conn.commit()
        conn.close()

        # Reset over-balance counter — legitimate transfer completed.
        self._reset_over_balance(user["id"])

        self._record_transfer(
            sender_id       = user["id"],
            recipient_phone = recipient["phone"],
            amount          = amount,
            transfer_type   = transfer_type,
            network         = recipient["network"],
            reference       = reference,
            status          = "completed",
            fraud_score     = fraud_score,
            ml_score        = ml_score,
            rule_score      = rule_score,
            risk_level      = risk_level,
            is_fraud        = False,
            face_verified   = bool(face_verified) if face_verified is not None else False,
            fee             = fee,
            notes           = fraud_result["message"],
        )

        return {
            "success"      : True,
            "action"       : "ALLOW",
            "message"      : "Transfer completed successfully.",
            "reference"    : reference,
            "recipient"    : recipient["phone"],
            "network"      : recipient["network"],
            "amount"       : amount,
            "fee"          : fee,
            "total"        : total,
            "fraud_score"  : fraud_score,
            "risk_level"   : risk_level,
            "face_verified": face_verified,
        }

    # ─────────────────────────────────────────────────────────────────────
    # ABROAD TRANSFER — save pending + email owner for face verify
    # ─────────────────────────────────────────────────────────────────────

    def _handle_abroad_transfer(self, user: dict, recipient_phone: str,
                                 amount: float, fee: float, transfer_type: str,
                                 destination: str, return_date: str) -> dict:
        """
        Someone is trying to use a SIM whose owner is abroad.
        Save the transfer as pending and email the owner a one-time face
        verification link.  The owner approves (face match) or ignores
        (transfer expires).
        """
        import secrets as _sec
        from datetime import datetime as _dt, timedelta as _td

        token = _sec.token_urlsafe(32)
        expires_at = _dt.now() + _td(hours=24)

        # Look up owner email
        conn = self.get_connection()
        c = conn.cursor()
        c.execute("SELECT email, full_name FROM users WHERE id = %s", (user["id"],))
        row = c.fetchone()
        owner_email = row[0] if row else None
        owner_name  = row[1] if row else "Account Owner"

        # Save pending transfer
        c.execute('''
            INSERT INTO abroad_pending_transfers
            (sender_id, recipient_phone, amount, fee, transfer_type,
             network, verify_token, status, destination, expires_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s)
        ''', (user["id"], recipient_phone, amount, fee, transfer_type,
              self._validate_recipient(recipient_phone)["network"],
              token, destination, expires_at))
        conn.commit()
        conn.close()

        # Send email with verification link
        verify_link = f"http://localhost:5173/abroad-verify?token={token}"
        if owner_email:
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart

                SMTP_HOST     = 'smtp.gmail.com'
                SMTP_PORT     = 587
                SMTP_USERNAME = 'ericuwinezastarboy@gmail.com'
                SMTP_PASSWORD = 'wagbvbyowxhbwrsg'

                msg = MIMEMultipart('alternative')
                msg['Subject'] = '⚠️ MoMo Shield — Transfer Attempt on Your SIM'
                msg['From']    = f'MoMo Shield <{SMTP_USERNAME}>'
                msg['To']      = owner_email

                html = f"""
                <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:30px;
                            border:1px solid #e2e8f0;border-radius:12px;">
                  <h2 style="color:#f59e0b;">⚠️ Transfer Attempt While You Are Abroad</h2>
                  <p>Hello <strong>{owner_name}</strong>,</p>
                  <p>Someone just tried to make a transfer from your MoMo account while you are abroad
                     in <strong>{destination}</strong>.</p>
                  <table style="border-collapse:collapse;width:100%;margin:16px 0;">
                    <tr><td style="padding:6px;color:#64748b;">Recipient</td>
                        <td style="padding:6px;font-weight:bold;">{recipient_phone}</td></tr>
                    <tr><td style="padding:6px;color:#64748b;">Amount</td>
                        <td style="padding:6px;font-weight:bold;">{amount:,.0f} RWF</td></tr>
                    <tr><td style="padding:6px;color:#64748b;">Fee</td>
                        <td style="padding:6px;">{fee:,.0f} RWF</td></tr>
                    <tr><td style="padding:6px;color:#64748b;">Total</td>
                        <td style="padding:6px;font-weight:bold;color:#10b981;">{(amount+fee):,.0f} RWF</td></tr>
                  </table>
                  <p>If <strong>you authorised this</strong>, click the button below and scan your face
                     to approve it. The link expires in <strong>24 hours</strong>.</p>
                  <a href="{verify_link}"
                     style="display:inline-block;margin:20px 0;padding:14px 32px;
                            background:linear-gradient(to right,#10b981,#0ea5e9);
                            color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;">
                    ✅ Approve Transfer with Face Scan
                  </a>
                  <p style="color:#ef4444;font-weight:bold;">
                    If you did NOT authorise this transfer, do NOT click the link.
                    The transfer will be automatically rejected after 24 hours.
                  </p>
                  <hr style="border:none;border-top:1px solid #e2e8f0;margin:20px 0;">
                  <p style="color:#94a3b8;font-size:11px;">
                    MoMo Shield — AI-Powered Mobile Money Fraud Detection
                  </p>
                </div>
                """
                msg.attach(MIMEText(html, 'html'))
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                    server.ehlo(); server.starttls()
                    server.login(SMTP_USERNAME, SMTP_PASSWORD)
                    server.sendmail(SMTP_USERNAME, owner_email, msg.as_string())
                print(f"[AbroadTransfer] Verification email sent to {owner_email}")
            except Exception as e:
                print(f"[AbroadTransfer] Email send failed: {e}")

        return {
            "success"      : False,
            "action"       : "ABROAD_PENDING",
            "abroad_pending": True,
            "message"      : (
                f"✈️ This SIM is registered as abroad in {destination}. "
                f"A verification email has been sent to the account owner at "
                f"{owner_email[:3]}***{owner_email[owner_email.index('@'):] if owner_email and '@' in owner_email else ''}. "
                f"The transfer of {amount:,.0f} RWF will be processed once the owner "
                f"approves it via face scan. Link expires in 24 hours."
            ),
            "owner_email_hint": (
                f"{owner_email[:3]}***{owner_email[owner_email.index('@'):]}"
                if owner_email and '@' in owner_email else "owner email"
            ),
        }

    def complete_abroad_transfer(self, token: str) -> dict:
        """
        Called after the abroad owner completes face verification.
        Executes the pending transfer: deduct sender balance, credit recipient.
        """
        conn = self.get_connection()
        c = conn.cursor()
        c.execute('''
            SELECT id, sender_id, recipient_phone, amount, fee,
                   transfer_type, network, destination, expires_at
            FROM abroad_pending_transfers
            WHERE verify_token = %s AND status = 'pending'
        ''', (token,))
        row = c.fetchone()

        if not row:
            conn.close()
            return {"success": False, "error": "Verification link is invalid or already used."}

        pid, sender_id, recipient_phone, amount, fee, \
            transfer_type, network, destination, expires_at = row

        from datetime import datetime as _dt
        if _dt.now() > expires_at:
            c.execute("UPDATE abroad_pending_transfers SET status='expired' WHERE id=%s", (pid,))
            conn.commit(); conn.close()
            return {"success": False, "error": "This verification link has expired."}

        total = amount + fee

        # Check sender still has enough balance
        c.execute("SELECT account_balance FROM users WHERE id=%s", (sender_id,))
        bal_row = c.fetchone()
        if not bal_row or bal_row[0] < total:
            c.execute("UPDATE abroad_pending_transfers SET status='failed' WHERE id=%s", (pid,))
            conn.commit(); conn.close()
            return {"success": False,
                    "error": f"Insufficient balance. Required {total:,.0f} RWF."}

        # Execute transfer
        reference = self._generate_reference()
        c.execute("UPDATE users SET account_balance = account_balance - %s WHERE id = %s",
                  (total, sender_id))
        c.execute("UPDATE users SET account_balance = account_balance + %s WHERE phone_number = %s AND is_active=TRUE",
                  (amount, recipient_phone))
        c.execute("UPDATE abroad_pending_transfers SET status='completed' WHERE id=%s", (pid,))
        conn.commit()
        conn.close()

        self._record_transfer(
            sender_id=sender_id, recipient_phone=recipient_phone,
            amount=amount, transfer_type=transfer_type, network=network,
            reference=reference, status="completed",
            fraud_score=0.1, ml_score=0.1, rule_score=0.0,
            risk_level="LOW", is_fraud=False, face_verified=True,
            fee=fee,
            notes=f"Abroad owner face-verified transfer. Destination: {destination}."
        )

        return {
            "success"  : True,
            "message"  : f"Transfer of {amount:,.0f} RWF to {recipient_phone} approved and completed.",
            "reference": reference,
            "amount"   : amount,
            "fee"      : fee,
            "total"    : total,
        }

    # ─────────────────────────────────────────────────────────────────────
    # RECORD HELPER
    # ─────────────────────────────────────────────────────────────────────

    def _record_transfer(self, sender_id, recipient_phone, amount,
                         transfer_type, network, reference, status,
                         fraud_score, ml_score, rule_score, risk_level,
                         is_fraud, face_verified, fee=0.0, notes=""):
        conn = self.get_connection()
        c = conn.cursor()
        completed_at = datetime.now() if status == "completed" else None
        c.execute('''
            INSERT INTO money_transfers
            (sender_id, recipient_phone, amount, fee, transfer_type, network,
             reference_number, status, fraud_score, ml_score, rule_score,
             risk_level, is_fraud, face_verified, completed_at, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ''', (sender_id, recipient_phone, amount, fee, transfer_type, network,
              reference, status, fraud_score, ml_score, rule_score,
              risk_level, is_fraud, face_verified, completed_at, notes))
        conn.commit()
        conn.close()

    # ─────────────────────────────────────────────────────────────────────
    # TRANSFER HISTORY
    # ─────────────────────────────────────────────────────────────────────

    def get_transfer_history(self, session_token: str, limit: int = 50) -> dict:
        user = self.auth.validate_session(session_token)
        if not user:
            return {"success": False, "error": "Invalid session."}

        conn = self.get_connection()
        c = conn.cursor()

        c.execute('''
            SELECT mt.reference_number, mt.recipient_phone, mt.amount,
                   COALESCE(mt.fee, 0), mt.network, mt.status, mt.fraud_score,
                   mt.risk_level, mt.is_fraud, mt.face_verified, mt.created_at,
                   mt.notes, u.phone_number, 'sent'
            FROM money_transfers mt
            JOIN users u ON mt.sender_id = u.id
            WHERE mt.sender_id = %s
            ORDER BY mt.created_at DESC LIMIT %s
        ''', (user["id"], limit))
        sent_rows = c.fetchall()

        c.execute('''
            SELECT mt.reference_number, mt.recipient_phone, mt.amount,
                   0, mt.network, mt.status, mt.fraud_score,
                   mt.risk_level, mt.is_fraud, mt.face_verified, mt.created_at,
                   mt.notes, u.phone_number, 'received'
            FROM money_transfers mt
            JOIN users u ON mt.sender_id = u.id
            WHERE mt.recipient_phone = %s AND mt.status = 'completed'
            ORDER BY mt.created_at DESC LIMIT %s
        ''', (user["phone"], limit))
        received_rows = c.fetchall()

        conn.close()

        all_rows = list(sent_rows) + list(received_rows)
        all_rows.sort(key=lambda x: x[10] or "", reverse=True)
        all_rows = all_rows[:limit]

        transfers = []
        for r in all_rows:
            transfers.append({
                "reference"    : r[0],
                "recipient"    : r[1],
                "amount"       : r[2],
                "fee"          : r[3],
                "network"      : r[4],
                "status"       : r[5],
                "fraud_score"  : r[6],
                "risk_level"   : r[7],
                "is_fraud"     : bool(r[8]),
                "face_verified": bool(r[9]),
                "created_at"   : r[10],
                "notes"        : r[11],
                "sender_phone" : r[12],
                "direction"    : r[13],
            })

        return {"success": True, "transfers": transfers}

    # ─────────────────────────────────────────────────────────────────────
    # NETWORK INFO
    # ─────────────────────────────────────────────────────────────────────

    def get_network_info(self, phone: str) -> dict:
        return self._validate_recipient(phone)

    def get_transfer_fee(self, phone: str, amount: float) -> dict:
        recipient = self._validate_recipient(phone)
        if not recipient["valid"]:
            return {"success": False, "error": "Invalid phone number."}
        fee   = self._calculate_fee(recipient["network"], amount)
        total = amount + fee
        return {
            "success": True,
            "network": recipient["network"],
            "amount" : amount,
            "fee"    : fee,
            "total"  : total,
        }
