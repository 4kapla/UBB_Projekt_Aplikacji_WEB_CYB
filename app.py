from datetime import datetime, timedelta
import secrets
import string
import sqlite3
from argon2 import PasswordHasher
from flask import Flask, flash, redirect, render_template_string, request, session, url_for

app = Flask(__name__)
app.secret_key = "boio"

ph = PasswordHasher()

DATABASE = "database.db"


def get_db():
  conn = sqlite3.connect(DATABASE)
  conn.row_factory = sqlite3.Row
  return conn


def get_setting(key, default_val):
  conn = get_db()
  cursor = conn.cursor()
  cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
  row = cursor.fetchone()
  conn.close()
  return row["value"] if row else default_val


def init_db():
  conn = get_db()
  cursor = conn.cursor()

  cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            is_first_login BOOLEAN DEFAULT 1,
            is_blocked BOOLEAN DEFAULT 0,
            password_changed_at TIMESTAMP,
            temp_password TEXT
        )
    """)

  cursor.execute(
      "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)"
  )

  default_settings = {
      "require_unique_chars": "1",  # Wariant 4: min 8 różnych znaków
      "password_expiry_days": "30",
      "session_timeout_minutes": "15",
  }
  for k, v in default_settings.items():
    cursor.execute(
        "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (k, v)
    )

  cursor.execute("SELECT COUNT(*) FROM users")
  if cursor.fetchone()[0] == 0:
    default_pass = ph.hash("PoczatkoweHaslo123!")
    now = datetime.now().isoformat()
    test_users = [
        ("admin", default_pass, "Administrator", now),
        ("audytor1", default_pass, "Audytor", now),
        ("redaktor1", default_pass, "Redaktor", now),
        ("redaktor2", default_pass, "Redaktor", now),
        ("czytelnik1", default_pass, "Czytelnik", now),
        ("czytelnik2", default_pass, "Czytelnik", now),
    ]
    cursor.executemany(
        """INSERT INTO users (username, password_hash, role, password_changed_at) 
               VALUES (?, ?, ?, ?)""",
        test_users,
    )
    conn.commit()
  conn.close()


@app.before_request
def security_checks():
  if "user_id" in session:
    now = datetime.now()
    timeout_min = int(get_setting("session_timeout_minutes", 15))
    last_activity = session.get("last_activity")

    if last_activity:
      delta = (now - datetime.fromisoformat(last_activity)).total_seconds()
      if delta > (timeout_min * 60):
        session.clear()
        flash("Sesja wygasła z powodu bezczynności. Zaloguj się ponownie.")
        return redirect(url_for("login"))

    session["last_activity"] = now.isoformat()


# --- NOWOCZESNY DARK THEME CSS ---
COMMON_STYLE = """
<style>
    :root {
        --bg-main: #0f172a;
        --bg-card: #1e293b;
        --bg-input: #334155;
        --border-color: #475569;
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
        --primary: #6366f1;
        --primary-hover: #4f46e5;
        --danger: #ef4444;
        --danger-hover: #dc2626;
        --warning: #f59e0b;
        --warning-hover: #d97706;
        --success: #10b981;
    }
    
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Inter, system-ui, sans-serif; background-color: var(--bg-main); color: var(--text-main); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    
    .container { background: var(--bg-card); padding: 32px; border-radius: 12px; border: 1px solid var(--border-color); box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); width: 100%; max-width: 950px; }
    
    h2 { font-size: 1.6rem; font-weight: 600; margin-bottom: 8px; color: #fff; }
    h3 { font-size: 1.2rem; font-weight: 600; margin-bottom: 16px; color: #e2e8f0; border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }
    
    p { color: var(--text-muted); font-size: 0.95rem; margin-bottom: 16px; }
    
    .flash { background: rgba(239, 68, 68, 0.15); border: 1px solid var(--danger); color: #fca5a5; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 0.9rem; }
    
    label { display: block; font-size: 0.875rem; font-weight: 500; color: var(--text-muted); margin-bottom: 6px; }
    
    input[type="text"], input[type="password"], input[type="number"], select {
        width: 100%; background: var(--bg-input); border: 1px solid var(--border-color); color: var(--text-main); padding: 10px 14px; border-radius: 6px; font-size: 0.95rem; outline: none; transition: border-color 0.2s;
    }
    input:focus, select:focus { border-color: var(--primary); }
    
    .btn { display: inline-block; background: var(--primary); color: #fff; border: none; padding: 10px 18px; border-radius: 6px; font-weight: 500; font-size: 0.9rem; cursor: pointer; text-decoration: none; transition: background 0.2s; text-align: center; }
    .btn:hover { background: var(--primary-hover); text-decoration: none; }
    .btn-danger { background: var(--danger); }
    .btn-danger:hover { background: var(--danger-hover); }
    .btn-warning { background: var(--warning); color: #000; }
    .btn-warning:hover { background: var(--warning-hover); }
    .btn-sm { padding: 5px 10px; font-size: 0.8rem; }
    
    .grid-form { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 16px; }
    
    .card-section { background: rgba(15, 23, 42, 0.4); border: 1px solid var(--border-color); padding: 20px; border-radius: 8px; margin-bottom: 24px; }
    
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th { background: #0f172a; color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.05em; padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }
    td { padding: 14px 12px; border-bottom: 1px solid var(--border-color); font-size: 0.9rem; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    
    code { background: #0f172a; padding: 4px 8px; border-radius: 4px; color: #38bdf8; font-family: monospace; border: 1px solid #334155; }
    
    .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }
    .badge-success { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: #fca5a5; }
    
    .header-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid var(--border-color); padding-bottom: 16px; }
</style>
"""

# --- CIEMNE SZABLONY HTML ---

LOGIN_TEMPLATE = (
    """
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Logowanie</title>"""
    + COMMON_STYLE
    + """</head>
<body>
<div class="container" style="max-width: 400px;">
    <h2>Logowanie</h2>
    <p>Wprowadź swoje poświadczenia</p>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}<div class="flash">{{ messages[0] }}</div>{% endif %}
    {% endwith %}
    
    <form method="post">
      <div style="margin-bottom: 16px;">
        <label>Nazwa użytkownika</label>
        <input type="text" name="username" required placeholder="np. admin">
      </div>
      <div style="margin-bottom: 24px;">
        <label>Hasło</label>
        <input type="password" name="password" required placeholder="••••••••••••">
      </div>
      <button type="submit" class="btn" style="width: 100%;">Zaloguj się</button>
    </form>
</div>
</body>
</html>
"""
)

CHANGE_PASSWORD_TEMPLATE = (
    """
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Zmiana hasła</title>"""
    + COMMON_STYLE
    + """</head>
<body>
<div class="container" style="max-width: 450px;">
    <h2>Zmiana hasła</h2>
    <p>Wymóg Wariantu 4: min. 16 znaków, min. 8 unikalnych znaków.</p>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}<div class="flash">{{ messages[0] }}</div>{% endif %}
    {% endwith %}
    
    <form method="post">
        <div style="margin-bottom: 16px;">
            <label>Nowe hasło</label>
            <input type="password" name="new_pass1" required placeholder="Wpisz nowe silne hasło">
        </div>
        <div style="margin-bottom: 24px;">
            <label>Powtórz nowe hasło</label>
            <input type="password" name="new_pass2" required placeholder="Powtórz nowe silne hasło">
        </div>
        <button type="submit" class="btn" style="width: 100%;">Zaktualizuj hasło</button>
    </form>
</div>
</body>
</html>
"""
)

ADMIN_TEMPLATE = (
    """
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Panel Administratora</title>"""
    + COMMON_STYLE
    + """</head>
<body>
<div class="container">
    <div class="header-bar">
        <div>
            <h2>Panel Administratora</h2>
            <p style="margin-bottom: 0;">Zalogowany jako: <b style="color: #fff;">{{ username }}</b></p>
        </div>
        <a href="{{ url_for('logout') }}" class="btn btn-danger btn-sm">Wyloguj</a>
    </div>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}<div class="flash">{{ messages[0] }}</div>{% endif %}
    {% endwith %}
    
    <div class="card-section">
        <h3>Ustawienia systemu i polityki haseł</h3>
        <form method="post" action="{{ url_for('update_settings') }}">
            <div class="grid-form">
                <div>
                    <label>Dodatkowa reguła (min. 8 unikalnych znaków)</label>
                    <select name="require_unique_chars">
                        <option value="1" {% if settings.require_unique_chars == '1' %}selected{% endif %}>Włączona</option>
                        <option value="0" {% if settings.require_unique_chars == '0' %}selected{% endif %}>Wyłączona</option>
                    </select>
                </div>
                <div>
                    <label>Ważność hasła (dni)</label>
                    <input type="number" name="password_expiry_days" value="{{ settings.password_expiry_days }}" required>
                </div>
                <div>
                    <label>Timeout sesji (minuty)</label>
                    <input type="number" name="session_timeout_minutes" value="{{ settings.session_timeout_minutes }}" required>
                </div>
            </div>
            <button type="submit" class="btn btn-sm">Zapisz konfigurację</button>
        </form>
    </div>

    <div class="card-section">
        <h3>Dodaj użytkownika</h3>
        <form method="post" action="{{ url_for('add_user') }}">
            <div class="grid-form">
                <div>
                    <label>Login</label>
                    <input type="text" name="username" placeholder="Nowy login" required>
                </div>
                <div>
                    <label>Rola w systemie</label>
                    <select name="role">
                        <option value="Administrator">Administrator</option>
                        <option value="Audytor">Audytor</option>
                        <option value="Redaktor">Redaktor</option>
                        <option value="Czytelnik">Czytelnik</option>
                    </select>
                </div>
                <div style="display: flex; align-items: flex-end;">
                    <button type="submit" class="btn btn-sm" style="width: 100%;">Utwórz konto z OTP</button>
                </div>
            </div>
        </form>
    </div>

    <h3>Użytkownicy w bazie</h3>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Login</th>
                <th>Rola</th>
                <th>Status</th>
                <th>Hasło jednorazowe (OTP)</th>
                <th>Akcje</th>
            </tr>
        </thead>
        <tbody>
            {% for u in users %}
            <tr>
                <td>#{{ u.id }}</td>
                <td><b style="color: #fff;">{{ u.username }}</b></td>
                <td><span style="color: var(--text-muted);">{{ u.role }}</span></td>
                <td>
                    {% if u.is_blocked %}
                        <span class="badge badge-danger">Zablokowany</span>
                    {% else %}
                        <span class="badge badge-success">Aktywny</span>
                    {% endif %}
                </td>
                <td><code>{{ u.temp_password if u.temp_password else '-' }}</code></td>
                <td>
                    <a href="{{ url_for('edit_user', user_id=u.id) }}" class="btn btn-sm" style="background: var(--bg-input);">Edytuj</a>
                    {% if not u.is_blocked %}
                        <a href="{{ url_for('toggle_block', user_id=u.id) }}" class="btn btn-warning btn-sm">Blokuj</a>
                    {% else %}
                        <a href="{{ url_for('toggle_block', user_id=u.id) }}" class="btn btn-sm" style="background: var(--success);">Odblokuj</a>
                    {% endif %}
                    <a href="{{ url_for('reset_otp', user_id=u.id) }}" class="btn btn-warning btn-sm" title="Generuje 10-znakowe OTP">OTP Reset</a>
                    {% if u.username != 'admin' %}
                        <a href="{{ url_for('delete_user', user_id=u.id) }}" class="btn btn-danger btn-sm" onclick="return confirm('Usunąć użytkownika?')">Usuń</a>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</div>
</body>
</html>
"""
)

EDIT_USER_TEMPLATE = (
    """
<!doctype html>
<html lang="pl">
<head><meta charset="utf-8"><title>Edycja Użytkownika</title>"""
    + COMMON_STYLE
    + """</head>
<body>
<div class="container" style="max-width: 450px;">
    <h2>Edycja: {{ user.username }}</h2>
    <p>Zmień przypisaną rolę w systemie</p>
    
    {% with messages = get_flashed_messages() %}
      {% if messages %}<div class="flash">{{ messages[0] }}</div>{% endif %}
    {% endwith %}
    
    <form method="post">
        <div style="margin-bottom: 20px;">
            <label>Rola</label>
            <select name="role">
                <option value="Administrator" {% if user.role == 'Administrator' %}selected{% endif %}>Administrator</option>
                <option value="Audytor" {% if user.role == 'Audytor' %}selected{% endif %}>Audytor</option>
                <option value="Redaktor" {% if user.role == 'Redaktor' %}selected{% endif %}>Redaktor</option>
                <option value="Czytelnik" {% if user.role == 'Czytelnik' %}selected{% endif %}>Czytelnik</option>
            </select>
        </div>
        <button type="submit" class="btn" style="width: 100%; margin-bottom: 12px;">Zapisz zmiany</button>
    </form>
    <a href="{{ url_for('admin_panel') }}" class="btn btn-sm" style="background: transparent; color: var(--text-muted); display: block; text-align: center;">Powrót do panelu</a>
</div>
</body>
</html>
"""
)


# --- ROUTING I KONTROLERY ---


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
  if request.method == "POST":
    username = request.form["username"]
    password = request.form["password"]

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()

    dummy_hash = "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$2K0g8..."
    login_failed = False

    if not user or user["is_blocked"]:
      try:
        ph.verify(dummy_hash, password)
      except:
        pass
      login_failed = True
    else:
      if user["temp_password"] and password == user["temp_password"]:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        return redirect(url_for("force_change_password"))
      try:
        ph.verify(user["password_hash"], password)
      except:
        login_failed = True

    if login_failed:
      flash("Login lub hasło niepoprawne")
      return render_template_string(LOGIN_TEMPLATE)

    if user["password_changed_at"]:
      expiry_days = int(get_setting("password_expiry_days", 30))
      pass_date = datetime.fromisoformat(user["password_changed_at"])
      if (datetime.now() - pass_date).days > expiry_days:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        flash(
            "Twoje hasło wygasło. Wymagana jest zmiana hasła zgodnie z"
            " polityką."
        )
        return redirect(url_for("force_change_password"))

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]

    if user["is_first_login"]:
      return redirect(url_for("force_change_password"))

    if user["role"] == "Administrator":
      return redirect(url_for("admin_panel"))
    else:
      return render_template_string(
          """
        <!doctype html>
        <html><head><title>Panel Użytkownika</title>"""
          + COMMON_STYLE
          + """</head>
        <body><div class="container" style="max-width: 500px;">
        <h2>Witaj, {{ username }}!</h2>
        <p>Rola w systemie: <b style="color: #fff;">{{ role }}</b></p>
        <a href="{{ url_for('logout') }}" class="btn btn-danger btn-sm">Wyloguj się</a>
        </div></body></html>
        """,
          username=user["username"],
          role=user["role"],
      )

  return render_template_string(LOGIN_TEMPLATE)


@app.route("/change-password", methods=["GET", "POST"])
def force_change_password():
  if "user_id" not in session:
    return redirect(url_for("login"))

  if request.method == "POST":
    new_pass1 = request.form["new_pass1"]
    new_pass2 = request.form["new_pass2"]

    if new_pass1 != new_pass2:
      flash("Nowe hasła muszą być identyczne.")
      return redirect(url_for("force_change_password"))

    if len(new_pass1) < 16:
      flash("Hasło musi mieć co najmniej 16 znaków.")
      return redirect(url_for("force_change_password"))

    if get_setting("require_unique_chars", "1") == "1":
      if len(set(new_pass1)) < 8:
        flash(
            "Polityka wymaga co najmniej 8 unikalnych znaków w"
            " haśle."
        )
        return redirect(url_for("force_change_password"))

    new_hash = ph.hash(new_pass1)
    now = datetime.now().isoformat()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """UPDATE users SET password_hash = ?, is_first_login = 0, 
                  password_changed_at = ?, temp_password = NULL WHERE id = ?""",
        (new_hash, now, session["user_id"]),
    )
    conn.commit()
    conn.close()

    flash("Hasło zostało pomyślnie zmienione.")
    return redirect(url_for("login"))

  return render_template_string(CHANGE_PASSWORD_TEMPLATE)


@app.route("/admin")
def admin_panel():
  if session.get("role") != "Administrator":
    return (
        "Brak uprawnień (403 Forbidden - Dostęp tylko dla Administratora)",
        403,
    )

  conn = get_db()
  cursor = conn.cursor()
  cursor.execute("SELECT * FROM users")
  users = cursor.fetchall()
  conn.close()

  settings = {
      "require_unique_chars": get_setting("require_unique_chars", "1"),
      "password_expiry_days": get_setting("password_expiry_days", "30"),
      "session_timeout_minutes": get_setting("session_timeout_minutes", "15"),
  }

  return render_template_string(
      ADMIN_TEMPLATE, users=users, settings=settings, username=session["username"]
  )


@app.route("/admin/settings", methods=["POST"])
def update_settings():
  if session.get("role") != "Administrator":
    return "Brak uprawnień", 403

  req_unique = request.form.get("require_unique_chars")
  exp_days = request.form.get("password_expiry_days")
  timeout_min = request.form.get("session_timeout_minutes")

  conn = get_db()
  cursor = conn.cursor()
  cursor.execute(
      "UPDATE settings SET value = ? WHERE key = 'require_unique_chars'",
      (req_unique,),
  )
  cursor.execute(
      "UPDATE settings SET value = ? WHERE key = 'password_expiry_days'",
      (exp_days,),
  )
  cursor.execute(
      "UPDATE settings SET value = ? WHERE key = 'session_timeout_minutes'",
      (timeout_min,),
  )
  conn.commit()
  conn.close()

  flash("Ustawienia systemowe zostały zaktualizowane.")
  return redirect(url_for("admin_panel"))


@app.route("/admin/user/add", methods=["POST"])
def add_user():
  if session.get("role") != "Administrator":
    return "Brak uprawnień", 403

  username = request.form["username"]
  role = request.form["role"]

  alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnopqrstuvwxyz"
  temp_pass = "".join(secrets.choice(alphabet) for _ in range(10))
  dummy_initial_hash = ph.hash(temp_pass)

  conn = get_db()
  cursor = conn.cursor()
  try:
    cursor.execute(
        """INSERT INTO users (username, password_hash, role, is_first_login, temp_password) 
               VALUES (?, ?, ?, 1, ?)""",
        (username, dummy_initial_hash, role, temp_pass),
    )
    conn.commit()
    flash(
        f"Dodano użytkownika {username}. Hasło jednorazowe (OTP): {temp_pass}"
    )
  except sqlite3.IntegrityError:
    flash("Użytkownik o takim loginie już istnieje.")
  conn.close()

  return redirect(url_for("admin_panel"))


@app.route("/admin/user/edit/<int:user_id>", methods=["GET", "POST"])
def edit_user(user_id):
  if session.get("role") != "Administrator":
    return "Brak uprawnień", 403

  conn = get_db()
  cursor = conn.cursor()

  if request.method == "POST":
    new_role = request.form["role"]
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    flash("Zaktualizowano dane użytkownika.")
    return redirect(url_for("admin_panel"))

  cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  user = cursor.fetchone()
  conn.close()

  return render_template_string(EDIT_USER_TEMPLATE, user=user)


@app.route("/admin/user/block/<int:user_id>")
def toggle_block(user_id):
  if session.get("role") != "Administrator":
    return "Brak uprawnień", 403

  conn = get_db()
  cursor = conn.cursor()
  cursor.execute(
      "UPDATE users SET is_blocked = NOT is_blocked WHERE id = ?", (user_id,)
  )
  conn.commit()
  conn.close()
  flash("Zmieniono status blokady użytkownika.")
  return redirect(url_for("admin_panel"))


@app.route("/admin/user/delete/<int:user_id>")
def delete_user(user_id):
  if session.get("role") != "Administrator":
    return "Brak uprawnień", 403

  conn = get_db()
  cursor = conn.cursor()
  cursor.execute("DELETE FROM users WHERE id = ? AND username != 'admin'", (user_id,))
  conn.commit()
  conn.close()
  flash("Usunięto użytkownika.")
  return redirect(url_for("admin_panel"))


@app.route("/admin/user/reset_otp/<int:user_id>")
def reset_otp(user_id):
  if session.get("role") != "Administrator":
    return "Brak uprawnień", 403

  alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789abcdefghijkmnopqrstuvwxyz"
  otp = "".join(secrets.choice(alphabet) for _ in range(10))

  conn = get_db()
  cursor = conn.cursor()
  cursor.execute(
      "UPDATE users SET temp_password = ?, is_first_login = 1 WHERE id = ?",
      (otp, user_id),
  )
  conn.commit()
  conn.close()
  flash(f"Zresetowano hasło. Nowe hasło jednorazowe (OTP): {otp}")
  return redirect(url_for("admin_panel"))


@app.route("/logout")
def logout():
  session.clear()
  flash("Wylogowano pomyślnie.")
  return redirect(url_for("login"))


if __name__ == "__main__":
  init_db()
  app.run(debug=True, port=5000)