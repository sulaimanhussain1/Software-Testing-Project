import os
import struct
import uuid
import zlib
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

import db

UPLOAD_DIR = os.environ.get("TESTBOARD_UPLOADS", os.path.join(db.BASE_DIR, "uploads"))


def png(width, height, rgb):
    raw = b""
    for y in range(height):
        band = 0.82 if (y // 12) % 2 else 1.0
        px = bytes(int(c * band) for c in rgb)
        raw += b"\x00" + px * width
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def main():
    if os.path.exists(db.DB_PATH):
        os.remove(db.DB_PATH)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    for old in os.listdir(UPLOAD_DIR):
        os.remove(os.path.join(UPLOAD_DIR, old))
    db.init_db()
    conn = db.connect()
    c = conn.cursor()
    base = datetime.now() - timedelta(days=12)

    def ts(days=0.0, hours=0.0):
        return (base + timedelta(days=days, hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    users = [
        ("Muhammad Shahrukh", "shahrukh", "41955", "admin"),
        ("Samaan Osama", "samaan", "41955", "qa"),
        ("Hanzalah", "hanzalah", "41955", "qa"),
        ("Muhammad Sulaiman", "sulaiman", "41955", "dev"),
        ("Muhammad Hamza", "hamza", "41955", "dev"),
    ]
    uid = {}
    for name, uname, pw, role in users:
        c.execute("INSERT INTO users (full_name, username, password_hash, role, created_at) VALUES (?,?,?,?,?)",
                  (name, uname, generate_password_hash(pw), role, ts(0)))
        uid[uname] = c.lastrowid

    tcs = [
        ("Valid credentials login redirect", "Login", "High", "1. Open login page\n2. Enter valid email and password\n3. Click Login", "User lands on dashboard with session", "samaan"),
        ("Invalid password shows error", "Login", "High", "1. Open login page\n2. Enter wrong password\n3. Click Login", "Red error 'Invalid credentials' is shown", "samaan"),
        ("New user registration", "Login", "High", "1. Open registration page\n2. Fill all fields\n3. Submit", "Account created and confirmation email sent", "samaan"),
        ("Add out-of-stock item to cart", "Cart", "High", "1. Open out-of-stock product\n2. Click Add to Cart", "Button disabled and warning toast shown", "samaan"),
        ("Add item to cart from product page", "Cart", "Medium", "1. Browse catalog\n2. Click Add to Cart\n3. Open cart drawer", "Cart badge increments and item is listed", "samaan"),
        ("Remove item from cart", "Cart", "Medium", "1. Open cart with 2 items\n2. Click remove on item 1", "Item removed, subtotal recalculated", "hanzalah"),
        ("Payment gateway timeout retry", "Checkout", "Critical", "1. Proceed to payment\n2. Simulate 15s timeout\n3. Click retry", "Graceful retry without double charge", "hanzalah"),
        ("Credit card checkout flow", "Checkout", "Critical", "1. Fill billing address\n2. Enter valid test card\n3. Confirm order", "Order confirmation page with Order ID", "hanzalah"),
        ("Profile avatar upload", "Profile", "Medium", "1. Go to Profile settings\n2. Upload JPG avatar\n3. Save", "Avatar updated and thumbnail refreshed", "hanzalah"),
        ("View order history", "Profile", "Low", "1. Open Profile\n2. Click Orders tab", "Past orders listed with status badges", "hanzalah"),
        ("Search returns relevant results", "Search", "Medium", "1. Type 'shoes' in search\n2. Press Enter", "Relevant products are listed", None),
        ("Password reset email", "Login", "High", "1. Click Forgot password\n2. Enter email\n3. Submit", "Reset email arrives within 1 minute", None),
    ]
    tc_id = {}
    for i, (title, mod, pri, steps, exp, qa) in enumerate(tcs, 1):
        c.execute("""INSERT INTO test_cases (title, module, priority, steps, expected, created_by, assigned_to,
                     assigned_by, assigned_at, due_date, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                  (title, mod, pri, steps, exp, uid["shahrukh"], uid[qa] if qa else None,
                   uid["shahrukh"] if qa else None, ts(0.2) if qa else None,
                   (datetime.now() + timedelta(days=3 + i % 4)).strftime("%Y-%m-%d") if qa else None, ts(0.1)))
        tc_id[i] = c.lastrowid

    execs = {
        1: ("Pass", "samaan", "Redirected to dashboard", 1.0),
        2: ("Pass", "samaan", "Error toast shown", 1.1),
        3: ("Fail", "samaan", "Confirmation email never arrived; account created but status stays 'pending'", 1.3),
        4: ("Fail", "samaan", "Add to Cart button still clickable for out-of-stock product", 1.5),
        6: ("Pass", "hanzalah", "Item removed", 2.0),
        7: ("Fail", "hanzalah", "Customer charged twice after clicking retry on timeout", 2.2),
        8: ("Pass", "hanzalah", "Order ID displayed", 2.4),
        9: ("Fail", "hanzalah", "PNG avatars over 2MB give a blank white page", 2.6),
    }
    ex_id = {}
    for n, (status, who, actual, d) in execs.items():
        c.execute("INSERT INTO executions (test_case_id, status, actual, build, executed_by, executed_at) VALUES (?,?,?,?,?,?)",
                  (tc_id[n], status, actual, "v1.4.2", uid[who], ts(d)))
        ex_id[n] = c.lastrowid

    def attach(bug_id, event_id, exec_id, name, who, when, rgb=(220, 90, 90)):
        stored = uuid.uuid4().hex + ".png"
        data = png(640, 360, rgb)
        with open(os.path.join(UPLOAD_DIR, stored), "wb") as fh:
            fh.write(data)
        c.execute("""INSERT INTO attachments (bug_id, event_id, execution_id, original_name, stored_name, mime, size,
                     uploaded_by, uploaded_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                  (bug_id, event_id, exec_id, name, stored, "image/png", len(data), uid[who], when))

    def event(bug_id, who, kind, body, when):
        c.execute("INSERT INTO bug_events (bug_id, user_id, kind, body, created_at) VALUES (?,?,?,?,?)",
                  (bug_id, uid[who], kind, body, when))
        return c.lastrowid

    def bug(n, tc, title, mod, sev, status, steps, exp, act, reporter, dev, created, assigned=None, fixed=None,
            closed=None, reopen=0):
        c.execute("""INSERT INTO bugs (bug_code, test_case_id, execution_id, title, module, severity, status, steps,
                     expected, actual, build, reported_by, assigned_to, assigned_by, assigned_at, created_at,
                     updated_at, fixed_at, closed_at, reopen_count)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (f"BUG-{n:03d}", tc_id.get(tc), ex_id.get(tc), title, mod, sev, status, steps, exp, act, "v1.4.2",
                   uid[reporter], uid[dev] if dev else None, uid["shahrukh"] if dev else None, assigned, created,
                   closed or fixed or assigned or created, fixed, closed, reopen))
        bid = c.lastrowid
        event(bid, reporter, "reported", "", created)
        attach(bid, None, ex_id.get(tc), "screenshot.png", reporter, created)
        if dev:
            event(bid, "shahrukh", "assigned", f"Assigned to {dict((u[1], u[0]) for u in users)[dev]}", assigned)
        return bid

    bug(1, 3, "Registration confirmation email not sent", "Login", "High", "New",
        tcs[2][3], tcs[2][4], execs[3][2], "samaan", None, ts(1.3))
    bug(2, 4, "Out-of-stock item can still be added to cart", "Cart", "High", "Assigned",
        tcs[3][3], tcs[3][4], execs[4][2], "samaan", "sulaiman", ts(1.5), ts(1.7))
    b3 = bug(3, 7, "Double charge after payment timeout retry", "Checkout", "Critical", "In Progress",
             tcs[6][3], tcs[6][4], execs[7][2], "hanzalah", "sulaiman", ts(2.2), ts(2.3))
    event(b3, "sulaiman", "started", "Started working on this bug", ts(2.5))
    b4 = bug(4, 9, "Large PNG avatar upload gives blank page", "Profile", "Medium", "Fixed",
             tcs[8][3], tcs[8][4], execs[9][2], "hanzalah", "hamza", ts(2.6), ts(2.7), fixed=ts(5.1))
    event(b4, "hamza", "started", "Started working on this bug", ts(3.0))
    e = event(b4, "hamza", "fixed", "Added server-side size check (max 2 MB) and a friendly error message. "
                                    "Large images are now resized before saving.", ts(5.1))
    attach(b4, e, None, "fix-proof.png", "hamza", ts(5.1), (90, 170, 110))
    b5 = bug(5, None, "Login button misaligned on mobile Safari", "Login", "Low", "Reopened",
             "1. Open login page on iPhone Safari\n2. Observe the Login button", "Button is centred", "Button overflows by 8px",
             "samaan", "hamza", ts(3.0), ts(3.1), reopen=1)
    event(b5, "hamza", "started", "Started working on this bug", ts(3.4))
    e = event(b5, "hamza", "fixed", "Adjusted padding in .login-btn", ts(4.0))
    event(b5, "samaan", "reopened", "Still overflowing on iPhone SE (375px wide). Screenshot attached.", ts(4.6))
    e2 = c.execute("SELECT MAX(id) FROM bug_events").fetchone()[0]
    attach(b5, e2, None, "iphone-se.png", "samaan", ts(4.6), (230, 160, 60))
    b6 = bug(6, None, "Typo in checkout page heading", "Checkout", "Low", "Closed",
             "Open checkout", "Heading says 'Checkout'", "Heading says 'Chekout'", "hanzalah", "sulaiman",
             ts(1.0), ts(1.1), fixed=ts(1.6), closed=ts(2.0))
    event(b6, "sulaiman", "fixed", "Fixed spelling in template.", ts(1.6))
    event(b6, "hanzalah", "closed", "Verified on v1.4.2 – looks good.", ts(2.0))
    b7 = bug(7, 2, "Wrong error text for invalid password", "Login", "Medium", "Closed",
             tcs[1][3], tcs[1][4], "Shows 'Something went wrong'", "samaan", "hamza",
             ts(0.8), ts(0.9), fixed=ts(3.2), closed=ts(4.0), reopen=1)
    event(b7, "hamza", "fixed", "Mapped 401 to the correct message.", ts(1.5))
    event(b7, "samaan", "reopened", "Message correct for email login but not for phone login.", ts(2.0))
    event(b7, "hamza", "fixed", "Handled phone login path too.", ts(3.2))
    event(b7, "samaan", "closed", "Both paths verified.", ts(4.0))

    notes = [("shahrukh", "BUG-001 reported (High) – needs assignment: Registration confirmation email not sent", 1),
             ("sulaiman", "BUG-002 assigned to you: Out-of-stock item can still be added to cart", 2),
             ("hanzalah", "BUG-004 marked Fixed – ready for QA verification", 4),
             ("hamza", "BUG-005 REOPENED by Samaan Osama", 5)]
    for who, msg, bid in notes:
        c.execute("INSERT INTO notifications (user_id, message, link, created_at) VALUES (?,?,?,?)",
                  (uid[who], msg, f"/bug/{bid}", ts(5)))

    conn.commit()
    conn.close()
    print("Demo data loaded.")
    print("  shahrukh / samaan / hanzalah / sulaiman / hamza   password: 41955")


if __name__ == "__main__":
    main()
