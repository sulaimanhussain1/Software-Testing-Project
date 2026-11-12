# TestBoard – Manual Testing & Bug Tracking (Flask)

One login, **three separate modes**:

| Mode | URL prefix | What they do |
|---|---|---|
| **Admin Panel** | `/admin` | Create users (QA / Developer / Admin), create test cases, **assign test cases → QA** and **bugs → Developers**, see all bugs, report dashboard |
| **QA Mode** | `/qa` | Run assigned test cases, **report bug + upload screenshots**, verify fixed bugs → **Close** or **Reopen** |
| **Developer Mode** | `/dev` | See only bugs assigned to them, **Start**, mark **Fixed with comment + upload** |

Everyone also gets: notifications bell, comments with file uploads on every bug, a **Report Dashboard** (`/reports`) with charts, filters and CSV export.

## Run

```bash
pip install -r requirements.txt
python seed_data.py     # optional: loads demo users, test cases, bugs (wipes DB)
python app.py           # http://127.0.0.1:5000
```

Logins (password for everyone: `41955`): `shahrukh` (Admin), `samaan` and `hanzalah` (QA), `sulaiman` and `hamza` (Developers). You can also type the full name, e.g. "Samaan Osama".

## Bug life-cycle

```
QA fails a test / reports bug  →  New
Admin assigns to developer     →  Assigned
Developer clicks Start         →  In Progress
Developer: Mark Fixed (+comment, +upload) → Fixed
QA verifies:   Close  → Closed
               Reopen (+comment) → Reopened → developer fixes again
```

## Files

* `app.py` – all routes, roles, workflow rules  ·  `db.py` – SQLite schema
* `templates/` – `admin/`, `qa/`, `dev/` pages + shared `bug_detail.html`, `reports.html`
* `static/css/` – `style.css` (original theme) + `app.css` (role themes, new components)
* `uploads/` – uploaded evidence (served only through `/files/<id>` after permission check)

## Notes

* Passwords are hashed; CSRF token on every form; uploads limited to 5 files × 10 MB, safe extensions only.
* Set `TESTBOARD_SECRET` env var in production; use a real WSGI server (gunicorn/waitress) instead of `python app.py`.
* The old `index.html` mock-up was removed – the Flask app replaces it.

## Hosting (short)
* Start command on a server: `gunicorn app:app` (Linux hosts) – on PythonAnywhere use the WSGI file with `from app import app as application`.
* The app needs a **persistent disk** (SQLite file `testboard.db` + `uploads/` folder). Free hosts with temporary disks will lose data.
* First start creates `shahrukh / 41955` (admin). Change the password after login, or run `python seed_data.py` once for demo data.
