# QR Attendance (Python + Streamlit)

This project was rewritten in Python to avoid external MongoDB connectivity issues.

It now runs as a single Streamlit app with:

- Admin register/login
- Time-based attendance sessions
- QR code generation for each session
- Student check-in from QR token link
- Duplicate prevention per session and student ID
- Session-wise and recent attendance views

Data is stored in local SQLite (`attendance.db`) so no external database is required.

## Local setup

1. Create and activate a virtual environment.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run the app:

```bash
streamlit run app.py
```

## Streamlit Cloud deployment

1. Push this folder to GitHub.
2. In Streamlit Cloud, create a new app and set:
   - Main file path: `app.py`
3. Deploy.

Optional environment variable:

- `PUBLIC_BASE_URL`  
  Set this to your deployed app URL (for example, `https://your-app-name.streamlit.app`) so generated QR links always point to the correct host.

## How to use

- Open app in Admin mode (default) to register and login.
- Create a session and share the QR or check-in link.
- Students open the QR link and submit attendance in Student mode.
