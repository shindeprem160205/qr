import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Optional
import hashlib

import qrcode
import streamlit as st


DB_PATH = Path("attendance.db")


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value)


def hash_password(password: str, salt: Optional[str] = None) -> str:
    salt_hex = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        120_000,
    )
    return f"{salt_hex}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hash_password(password, salt_hex) == stored


def init_db() -> None:
    conn = get_connection()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES admins(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS attendance_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL,
            student_identifier TEXT NOT NULL,
            student_name TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE,
            UNIQUE(session_id, student_identifier)
        );
        """
    )
    conn.commit()
    conn.close()


def register_admin(email: str, password: str) -> None:
    norm_email = email.strip().lower()
    if not norm_email:
        raise ValueError("Email is required.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO admins (email, password_hash, created_at) VALUES (?, ?, ?)",
            (norm_email, hash_password(password), to_iso(now_utc())),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError("Email already registered.") from exc
    finally:
        conn.close()


def login_admin(email: str, password: str) -> dict:
    norm_email = email.strip().lower()
    conn = get_connection()
    row = conn.execute(
        "SELECT id, email, password_hash FROM admins WHERE email = ?",
        (norm_email,),
    ).fetchone()
    conn.close()

    if not row or not verify_password(password, row["password_hash"]):
        raise ValueError("Invalid email or password.")
    return {"id": row["id"], "email": row["email"]}


def create_session(admin_id: int, title: str, duration_minutes: int) -> dict:
    clean_title = title.strip()
    if not clean_title:
        raise ValueError("Session title is required.")
    if duration_minutes < 1 or duration_minutes > 1440:
        raise ValueError("Duration must be between 1 and 1440 minutes.")

    created_at = now_utc()
    expires_at = created_at + timedelta(minutes=duration_minutes)
    token = secrets.token_hex(24)

    conn = get_connection()
    cursor = conn.execute(
        """
        INSERT INTO sessions (title, token, expires_at, created_by, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (clean_title, token, to_iso(expires_at), admin_id, to_iso(created_at)),
    )
    conn.commit()
    session_id = cursor.lastrowid
    conn.close()

    return {
        "id": session_id,
        "title": clean_title,
        "token": token,
        "expires_at": expires_at,
        "created_at": created_at,
    }


def get_session_by_token(token: str) -> Optional[sqlite3.Row]:
    conn = get_connection()
    row = conn.execute(
        """
        SELECT s.id, s.title, s.token, s.expires_at, s.created_by, a.email AS admin_email
        FROM sessions s
        JOIN admins a ON a.id = s.created_by
        WHERE s.token = ?
        """,
        (token.strip(),),
    ).fetchone()
    conn.close()
    return row


def list_admin_sessions(admin_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT id, title, token, expires_at, created_at
        FROM sessions
        WHERE created_by = ?
        ORDER BY created_at DESC
        """,
        (admin_id,),
    ).fetchall()
    conn.close()
    return rows


def list_admin_records(admin_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT r.id, r.student_identifier, r.student_name, r.created_at, s.title AS session_title
        FROM attendance_records r
        JOIN sessions s ON s.id = r.session_id
        WHERE s.created_by = ?
        ORDER BY r.created_at DESC
        LIMIT 200
        """,
        (admin_id,),
    ).fetchall()
    conn.close()
    return rows


def list_records_for_session(session_id: int) -> list[sqlite3.Row]:
    conn = get_connection()
    rows = conn.execute(
        """
        SELECT id, student_identifier, student_name, created_at
        FROM attendance_records
        WHERE session_id = ?
        ORDER BY created_at DESC
        """,
        (session_id,),
    ).fetchall()
    conn.close()
    return rows


def check_in(token: str, student_identifier: str, student_name: str) -> dict:
    session = get_session_by_token(token)
    if not session:
        raise ValueError("Invalid or unknown QR token.")

    expires_at = parse_iso(session["expires_at"])
    if expires_at <= now_utc():
        raise TimeoutError("This attendance window has expired.")

    norm_id = student_identifier.strip().lower()
    if not norm_id:
        raise ValueError("Student ID or email is required.")
    clean_name = student_name.strip()

    conn = get_connection()
    try:
        cursor = conn.execute(
            """
            INSERT INTO attendance_records (session_id, student_identifier, student_name, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                session["id"],
                norm_id,
                clean_name if clean_name else None,
                to_iso(now_utc()),
            ),
        )
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise FileExistsError(
            "Attendance already recorded for this student in this session."
        ) from exc
    finally:
        conn.close()

    return {
        "id": cursor.lastrowid,
        "session_title": session["title"],
        "student_identifier": norm_id,
    }


def make_qr_png(data: str) -> bytes:
    img = qrcode.make(data)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    return buffer.getvalue()


def normalize_base_url(value: str) -> str:
    return value.strip().rstrip("/")


def get_default_base_url() -> str:
    custom = normalize_base_url(os.getenv("PUBLIC_BASE_URL", ""))
    if custom:
        return custom
    return "https://your-app-name.streamlit.app"


def get_base_url() -> str:
    manual = normalize_base_url(st.session_state.get("base_url", ""))
    if manual:
        return manual
    return get_default_base_url()


def session_active(expires_at: str) -> bool:
    return parse_iso(expires_at) > now_utc()


def format_dt(value: str) -> str:
    return parse_iso(value).astimezone().strftime("%Y-%m-%d %H:%M:%S")


def show_admin_ui() -> None:
    st.title("QR Attendance Admin")
    st.caption("Create sessions, share QR links, and review attendance.")

    if "admin_user" not in st.session_state:
        st.session_state.admin_user = None
    if "base_url" not in st.session_state:
        st.session_state.base_url = get_default_base_url()

    if st.session_state.admin_user is None:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Register")
            with st.form("register_form"):
                email = st.text_input("Email")
                password = st.text_input("Password (min 8 chars)", type="password")
                submitted = st.form_submit_button("Register")
                if submitted:
                    try:
                        register_admin(email, password)
                        st.success("Registered successfully. Please log in.")
                    except ValueError as exc:
                        st.error(str(exc))

        with col2:
            st.subheader("Login")
            with st.form("login_form"):
                email = st.text_input("Login email")
                password = st.text_input("Login password", type="password")
                submitted = st.form_submit_button("Login")
                if submitted:
                    try:
                        st.session_state.admin_user = login_admin(email, password)
                        st.rerun()
                    except ValueError as exc:
                        st.error(str(exc))
        return

    user = st.session_state.admin_user
    top_left, top_right = st.columns([4, 1])
    with top_left:
        st.success(f"Logged in as {user['email']}")
    with top_right:
        if st.button("Logout"):
            st.session_state.admin_user = None
            st.rerun()

    st.subheader("Phone access link settings")
    st.caption(
        "Set the URL your students can open on mobile. "
        "Use your deployed Streamlit URL or your computer IP URL."
    )
    st.text_input(
        "Public app URL",
        key="base_url",
        help="Example: https://your-app-name.streamlit.app or http://192.168.1.5:8501",
    )
    current_base_url = normalize_base_url(st.session_state.get("base_url", ""))
    if "your-app-name.streamlit.app" in current_base_url:
        st.warning(
            "Update the Public app URL above before sharing QR. "
            "The current value is a placeholder and will not open on phones."
        )

    st.subheader("Create new session")
    with st.form("create_session_form"):
        title = st.text_input("Session title", placeholder="e.g. CS101 - Week 3")
        duration = st.number_input(
            "Active duration (minutes)",
            min_value=1,
            max_value=1440,
            value=15,
            step=1,
        )
        created = st.form_submit_button("Generate QR")
        if created:
            try:
                session = create_session(user["id"], title, int(duration))
                base_url = get_base_url()
                checkin_url = f"{base_url}?mode=student&token={session['token']}"
                qr_bytes = make_qr_png(checkin_url)
                st.info("Session created.")
                st.code(checkin_url)
                st.image(qr_bytes, caption=f"QR for {session['title']}", width=280)
            except ValueError as exc:
                st.error(str(exc))

    st.subheader("Your sessions")
    sessions = list_admin_sessions(user["id"])
    if not sessions:
        st.caption("No sessions yet.")
    for row in sessions:
        active = session_active(row["expires_at"])
        badge = "active" if active else "expired"
        with st.expander(f"{row['title']} ({badge}) - ends {format_dt(row['expires_at'])}"):
            base_url = get_base_url()
            checkin_url = f"{base_url}?mode=student&token={row['token']}"
            st.write("Check-in link:")
            st.code(checkin_url)
            st.image(make_qr_png(checkin_url), caption="Session QR", width=260)
            records = list_records_for_session(row["id"])
            if records:
                st.dataframe(
                    [
                        {
                            "Time": format_dt(r["created_at"]),
                            "Student ID": r["student_identifier"],
                            "Name": r["student_name"] or "-",
                        }
                        for r in records
                    ],
                    use_container_width=True,
                )
            else:
                st.caption("No check-ins yet.")

    st.subheader("Recent attendance")
    records = list_admin_records(user["id"])
    if records:
        st.dataframe(
            [
                {
                    "Time": format_dt(r["created_at"]),
                    "Student ID": r["student_identifier"],
                    "Name": r["student_name"] or "-",
                    "Session": r["session_title"],
                }
                for r in records
            ],
            use_container_width=True,
        )
    else:
        st.caption("No records yet.")


def show_student_ui(token: str) -> None:
    st.title("Student Check-in")
    if not token:
        st.error("No token provided. Scan the QR code or use full check-in link.")
        return

    session = get_session_by_token(token)
    if not session:
        st.error("Invalid or unknown QR token.")
        return

    if parse_iso(session["expires_at"]) <= now_utc():
        st.warning("This attendance window has expired.")
        return

    st.subheader(session["title"])
    st.caption(f"Check in before: {format_dt(session['expires_at'])}")

    with st.form("checkin_form"):
        student_id = st.text_input("Student ID or email")
        student_name = st.text_input("Name (optional)")
        submitted = st.form_submit_button("Submit attendance")
        if submitted:
            try:
                output = check_in(token, student_id, student_name)
                st.success(
                    f"Attendance recorded for {output['student_identifier']} in {output['session_title']}."
                )
            except TimeoutError as exc:
                st.warning(str(exc))
            except FileExistsError as exc:
                st.error(str(exc))
            except ValueError as exc:
                st.error(str(exc))


def main() -> None:
    st.set_page_config(page_title="QR Attendance", page_icon="✅", layout="wide")
    init_db()

    mode = st.query_params.get("mode", "admin")
    token = st.query_params.get("token", "")
    if isinstance(mode, list):
        mode = mode[0] if mode else "admin"
    if isinstance(token, list):
        token = token[0] if token else ""

    with st.sidebar:
        st.header("Navigation")
        st.write("Open as admin or student.")
        if st.button("Go to Admin"):
            st.query_params.clear()
            st.query_params["mode"] = "admin"
            st.rerun()
        if st.button("Go to Student"):
            st.query_params["mode"] = "student"
            st.rerun()

    if mode == "student":
        show_student_ui(str(token))
    else:
        show_admin_ui()


if __name__ == "__main__":
    main()
