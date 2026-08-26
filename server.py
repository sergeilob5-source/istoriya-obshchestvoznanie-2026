# -*- coding: utf-8 -*-
"""
Сервер учебного портала «История и Обществознание» с авторизацией
и публикацией защищённой версии сайта на GitHub Pages.

Запуск:  python server.py            (порт 8741)
         python server.py 8080       (свой порт)

Как это устроено:
  * pages/            — исходные (открытые) страницы сайта; в git НЕ попадают.
  * server.py         — локальный сервер: вход по логину/паролю + админ-панель.
  * Кнопка «Опубликовать на GitHub» в админ-панели шифрует страницы и
    отправляет на GitHub Pages ТОЛЬКО шифротекст. Посетитель публичного
    сайта вводит логин и пароль — страницы расшифровываются в его браузере.
  * users.json        — локальная база пользователей (в git не попадает).
    Для каждого пользователя хранится PBKDF2-хеш пароля (для локального
    входа) и «ключ-обёртка» (для шифрования мастер-ключа сайта).
  * При каждой публикации создаётся НОВЫЙ мастер-ключ: удалённый
    пользователь после следующей публикации войти не сможет.

При первом запуске создаётся администратор:  admin / admin2026
Обязательно смените пароль после первого входа!
"""

import base64
import hashlib
import hmac as hmac_mod
import http.cookies
import http.server
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PAGES_DIR = os.path.join(BASE_DIR, "pages")
USERS_FILE = os.path.join(BASE_DIR, "users.json")
TEMPLATE_FILE = os.path.join(BASE_DIR, "protected_template.html")
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8741

ITERATIONS = 200_000

FORBIDDEN = {"server.py", "users.json"}
PUBLIC = {"/style.css", "/favicon.ico"}

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".json": "application/json; charset=utf-8",
}

# ---------- криптография (stdlib: HMAC-SHA256-CTR + encrypt-then-MAC) ----------

def pbkdf2(password: str, salt_hex: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt_hex), ITERATIONS, dklen=32)


def _hmac(key: bytes, data: bytes) -> bytes:
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += _hmac(key, nonce + counter.to_bytes(4, "little"))
        counter += 1
    return out[:length]


def seal(master: bytes, plaintext: bytes) -> dict:
    """Шифрует plaintext ключом master. Возвращает {n, ct, tag} в base64."""
    enc_key = _hmac(master, b"enc")
    mac_key = _hmac(master, b"mac")
    nonce = secrets.token_bytes(16)
    ks = _keystream(enc_key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = _hmac(mac_key, nonce + ct)
    b64 = lambda b: base64.b64encode(b).decode("ascii")
    return {"n": b64(nonce), "ct": b64(ct), "tag": b64(tag)}


# ---------- пользователи ----------

def make_user(password: str, role: str, name: str) -> dict:
    login_salt = secrets.token_hex(16)
    wrap_salt = secrets.token_hex(16)
    return {
        "salt": login_salt,
        "hash": pbkdf2(password, login_salt).hex(),
        "wrap_salt": wrap_salt,
        "wrap_key": pbkdf2(password, wrap_salt).hex(),
        "role": role,
        "name": name,
    }


def load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        users = {"admin": make_user("admin2026", "admin", "Администратор")}
        save_users(users)
        print("Создан администратор по умолчанию: admin / admin2026 — смените пароль!")
        return users
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users: dict) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)


def check_password(users: dict, login: str, password: str) -> bool:
    u = users.get(login)
    if not u:
        return False
    return secrets.compare_digest(u["hash"], pbkdf2(password, u["salt"]).hex())


SESSIONS: dict[str, str] = {}  # token -> login


# ---------- публикация на GitHub ----------

def publish_site() -> tuple[bool, str]:
    """Шифрует страницы новым мастер-ключом и пушит на GitHub. Возвращает (успех, журнал)."""
    log = []
    users = load_users()
    no_wrap = [l for l, u in users.items() if not u.get("wrap_key")]
    if no_wrap:
        return False, ("У пользователей нет ключа шифрования (созданы старой версией): "
                       + ", ".join(no_wrap)
                       + ". Смените им пароль в админ-панели и повторите публикацию.")

    with open(TEMPLATE_FILE, "r", encoding="utf-8") as f:
        template = f.read()

    master = secrets.token_bytes(32)

    users_pub = {}
    for login, u in users.items():
        box = seal(bytes.fromhex(u["wrap_key"]), master)
        users_pub[login] = {"salt": u["wrap_salt"], **box}
    users_json = json.dumps(users_pub, ensure_ascii=False)

    count = 0
    for fname in sorted(os.listdir(PAGES_DIR)):
        if not fname.endswith(".html"):
            continue
        with open(os.path.join(PAGES_DIR, fname), "r", encoding="utf-8") as f:
            html = f.read()
        m = re.search(r"<title>(.*?)</title>", html, re.S)
        title = m.group(1).strip() if m else "Учебный портал"
        payload = json.dumps(seal(master, html.encode("utf-8")), ensure_ascii=False)
        page = (template.replace("__TITLE__", title)
                        .replace("__USERS__", users_json)
                        .replace("__PAYLOAD__", payload))
        with open(os.path.join(BASE_DIR, fname), "w", encoding="utf-8") as f:
            f.write(page)
        count += 1
    log.append(f"Зашифровано страниц: {count}, пользователей с доступом: {len(users_pub)}.")

    def git(*args):
        r = subprocess.run(["git", *args], cwd=BASE_DIR, capture_output=True,
                           text=True, encoding="utf-8", errors="replace")
        return r.returncode, (r.stdout + r.stderr).strip()

    git("add", "-A")
    code, out = git("commit", "-m", "Обновление защищённого сайта")
    if code != 0 and "nothing to commit" not in out:
        return False, "\n".join(log) + "\nОшибка git commit:\n" + out
    if "nothing to commit" in out:
        log.append("Изменений для публикации нет (git).")
    code, out = git("push")
    if code != 0:
        return False, "\n".join(log) + "\nОшибка git push:\n" + out
    log.append("Отправлено на GitHub. Сайт обновится через 1–2 минуты.")
    return True, "\n".join(log)


# ---------- HTML-шаблоны локального сервера ----------

PAGE_TOP = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<link rel="stylesheet" href="/style.css">
<style>
.auth-box {{ max-width: 420px; margin: 60px auto; background: var(--card);
  border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow); padding: 32px 34px; }}
.auth-box h1 {{ font-size: 1.4rem; margin: 0 0 18px; }}
.auth-box label {{ display: block; margin: 12px 0 4px; font-size: .95rem; }}
.auth-box input {{ width: 100%; box-sizing: border-box; padding: 10px 12px; font-size: 1rem;
  border: 1px solid var(--line); border-radius: 8px; font-family: inherit; }}
.auth-box button, .admin button {{ margin-top: 18px; width: 100%; padding: 12px;
  font-size: 1.05rem; font-family: inherit; color: #fff; background: var(--soc);
  border: none; border-radius: 8px; cursor: pointer; }}
.auth-box button:hover, .admin button:hover {{ background: #17486a; }}
.error {{ background: #fdecea; color: #a4362a; border-radius: 8px;
  padding: 10px 14px; margin-bottom: 6px; font-size: .95rem; }}
.ok {{ background: #e8f4e8; color: #2c6b2f; border-radius: 8px;
  padding: 10px 14px; margin-bottom: 6px; font-size: .95rem; white-space: pre-line; }}
.admin table {{ width: 100%; border-collapse: collapse; background: var(--card);
  border-radius: var(--radius); overflow: hidden; box-shadow: var(--shadow); }}
.admin th, .admin td {{ text-align: left; padding: 10px 14px;
  border-bottom: 1px solid var(--line); }}
.admin th {{ background: var(--soc-soft); }}
.admin form.inline {{ display: inline; }}
.admin .danger {{ background: var(--hist); width: auto; margin: 0;
  padding: 6px 14px; font-size: .9rem; }}
.admin .danger:hover {{ background: #7c2f24; }}
.admin .publish {{ background: #2c6b2f; width: auto; padding: 12px 28px; margin-top: 8px; }}
.admin .publish:hover {{ background: #1f4f22; }}
.admin fieldset {{ border: 1px solid var(--line); border-radius: var(--radius);
  background: var(--card); padding: 18px 22px; margin: 22px 0; }}
.admin fieldset input, .admin fieldset select {{ padding: 8px 10px; margin: 4px 8px 4px 0;
  border: 1px solid var(--line); border-radius: 8px; font-family: inherit; }}
.admin fieldset button {{ width: auto; margin-top: 8px; padding: 9px 22px; }}
</style>
</head>
<body>
<header class="site"><div class="wrap">
  <a class="logo" href="/">История&nbsp;и&nbsp;Обществознание <span class="year">· 2026</span></a>
  <nav class="top">{nav}</nav>
</div></header>
<main class="wrap">
"""

PAGE_BOTTOM = """
</main>
<footer class="site"><div class="wrap">Учебный портал «История и Обществознание» · доступ по учётным записям</div></footer>
</body></html>"""

NAV_ANON = ""
NAV_USER = ('<a href="/istoriya.html">История</a>'
            '<a href="/obshchestvoznanie.html">Обществознание</a>'
            '<a href="/ege-oge.html">ЕГЭ и ОГЭ</a>'
            '<a href="/logout">Выйти ({login})</a>')
NAV_ADMIN = ('<a href="/istoriya.html">История</a>'
             '<a href="/obshchestvoznanie.html">Обществознание</a>'
             '<a href="/ege-oge.html">ЕГЭ и ОГЭ</a>'
             '<a href="/admin">Админ-панель</a>'
             '<a href="/logout">Выйти ({login})</a>')

LOGIN_FORM = """
<div class="auth-box">
  <h1>Вход на учебный портал</h1>
  {message}
  <form method="post" action="/login">
    <label for="login">Логин</label>
    <input id="login" name="login" required autofocus autocomplete="username">
    <label for="password">Пароль</label>
    <input id="password" name="password" type="password" required autocomplete="current-password">
    <button type="submit">Войти</button>
  </form>
  <p style="color:var(--muted);font-size:.85rem;margin-top:16px">
  Учётные записи выдаёт администратор портала. Если у вас нет логина и пароля —
  обратитесь к преподавателю.</p>
</div>
"""


def esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# ---------- HTTP-обработчик ----------

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "EduPortal/2.0"

    # --- утилиты ---

    def send_html(self, html: str, status: int = 200, cookies: list[str] | None = None):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for c in cookies or []:
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, cookies: list[str] | None = None):
        self.send_response(303)
        self.send_header("Location", location)
        for c in cookies or []:
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def current_user(self):
        cookie_header = self.headers.get("Cookie", "")
        cookies = http.cookies.SimpleCookie(cookie_header)
        token = cookies.get("session")
        if token and token.value in SESSIONS:
            login = SESSIONS[token.value]
            users = load_users()
            if login in users:
                return login, users[login]
        return None, None

    def read_post(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def nav_for(self, login: str, user: dict) -> str:
        tpl = NAV_ADMIN if user.get("role") == "admin" else NAV_USER
        return tpl.format(login=esc(login))

    # --- GET ---

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        login, user = self.current_user()

        if path == "/login":
            self.send_html(PAGE_TOP.format(title="Вход", nav=NAV_ANON)
                           + LOGIN_FORM.format(message="") + PAGE_BOTTOM)
            return

        if path == "/logout":
            cookie_header = self.headers.get("Cookie", "")
            cookies = http.cookies.SimpleCookie(cookie_header)
            token = cookies.get("session")
            if token:
                SESSIONS.pop(token.value, None)
            self.redirect("/login", ["session=; Path=/; Max-Age=0; HttpOnly"])
            return

        if path in PUBLIC:
            self.serve_static(path)
            return

        if not login:
            self.redirect("/login")
            return

        if path == "/admin":
            if user.get("role") != "admin":
                self.send_html(PAGE_TOP.format(title="Нет доступа",
                                               nav=self.nav_for(login, user))
                               + '<div class="auth-box"><h1>Доступ запрещён</h1>'
                                 '<p>Админ-панель доступна только администратору.</p></div>'
                               + PAGE_BOTTOM, status=403)
                return
            self.render_admin(login, user)
            return

        self.serve_static(path)

    # --- POST ---

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path

        if path == "/login":
            data = self.read_post()
            users = load_users()
            login = data.get("login", "").strip()
            password = data.get("password", "")
            if check_password(users, login, password):
                token = secrets.token_urlsafe(32)
                SESSIONS[token] = login
                self.redirect("/", [f"session={token}; Path=/; HttpOnly; SameSite=Lax"])
            else:
                msg = '<div class="error">Неверный логин или пароль.</div>'
                self.send_html(PAGE_TOP.format(title="Вход", nav=NAV_ANON)
                               + LOGIN_FORM.format(message=msg) + PAGE_BOTTOM, status=401)
            return

        login, user = self.current_user()
        if not login or user.get("role") != "admin":
            self.redirect("/login")
            return

        users = load_users()
        data = self.read_post()

        if path == "/admin/add":
            new_login = data.get("login", "").strip()
            new_pass = data.get("password", "")
            name = data.get("name", "").strip()
            role = "admin" if data.get("role") == "admin" else "user"
            if not new_login or not new_pass:
                self.render_admin(login, user, error="Логин и пароль обязательны.")
            elif new_login in users:
                self.render_admin(login, user, error=f"Пользователь «{esc(new_login)}» уже существует.")
            else:
                users[new_login] = make_user(new_pass, role, name)
                save_users(users)
                self.render_admin(login, user,
                                  ok=f"Пользователь «{esc(new_login)}» создан. Чтобы доступ появился "
                                     f"на публичном сайте — нажмите «Опубликовать на GitHub».")
            return

        if path == "/admin/delete":
            target = data.get("login", "")
            if target == login:
                self.render_admin(login, user, error="Нельзя удалить самого себя.")
            elif target in users:
                del users[target]
                save_users(users)
                for t, l in list(SESSIONS.items()):
                    if l == target:
                        del SESSIONS[t]
                self.render_admin(login, user,
                                  ok=f"Пользователь «{esc(target)}» удалён. Чтобы закрыть ему доступ "
                                     f"на публичном сайте — нажмите «Опубликовать на GitHub».")
            else:
                self.render_admin(login, user, error="Пользователь не найден.")
            return

        if path == "/admin/password":
            target = data.get("login", "")
            new_pass = data.get("password", "")
            if target not in users:
                self.render_admin(login, user, error="Пользователь не найден.")
            elif not new_pass:
                self.render_admin(login, user, error="Пароль не может быть пустым.")
            else:
                old = users[target]
                users[target] = make_user(new_pass, old.get("role", "user"), old.get("name", ""))
                save_users(users)
                self.render_admin(login, user,
                                  ok=f"Пароль для «{esc(target)}» изменён. Для публичного сайта — "
                                     f"нажмите «Опубликовать на GitHub».")
            return

        if path == "/admin/publish":
            ok_flag, out = publish_site()
            if ok_flag:
                self.render_admin(login, user, ok="Публикация выполнена.\n" + out)
            else:
                self.render_admin(login, user, error="Публикация не удалась.<br>"
                                  + esc(out).replace("\n", "<br>"))
            return

        self.send_html("Not found", status=404)

    # --- админ-панель ---

    def render_admin(self, login: str, user: dict, error: str = "", ok: str = ""):
        users = load_users()
        rows = []
        for u_login, u in sorted(users.items()):
            role = "администратор" if u.get("role") == "admin" else "ученик"
            delete_btn = ""
            if u_login != login:
                delete_btn = (f'<form class="inline" method="post" action="/admin/delete" '
                              f'onsubmit="return confirm(\'Удалить пользователя {esc(u_login)}?\')">'
                              f'<input type="hidden" name="login" value="{esc(u_login)}">'
                              f'<button class="danger">Удалить</button></form>')
            rows.append(f"<tr><td>{esc(u_login)}</td><td>{esc(u.get('name') or '—')}</td>"
                        f"<td>{role}</td><td>{delete_btn}</td></tr>")

        msg = ""
        if error:
            msg = f'<div class="error">{error}</div>'
        elif ok:
            msg = f'<div class="ok">{esc(ok)}</div>'

        html = (PAGE_TOP.format(title="Админ-панель", nav=self.nav_for(login, user))
                + f"""
<div class="admin">
  <div class="page-head"><h1>🛠 Панель администратора</h1>
  <p class="lead">Создание и удаление учётных записей, смена паролей, публикация
  защищённого сайта на GitHub Pages. Логины и пароли выдавайте ученикам лично.</p></div>
  {msg}
  <h2>Пользователи</h2>
  <table>
    <tr><th>Логин</th><th>Имя</th><th>Роль</th><th></th></tr>
    {''.join(rows)}
  </table>

  <fieldset>
    <legend><strong>Создать пользователя</strong></legend>
    <form method="post" action="/admin/add">
      <input name="login" placeholder="Логин" required>
      <input name="name" placeholder="Имя (необязательно)">
      <input name="password" type="text" placeholder="Пароль" required>
      <select name="role">
        <option value="user">Ученик</option>
        <option value="admin">Администратор</option>
      </select>
      <button type="submit">Создать</button>
    </form>
  </fieldset>

  <fieldset>
    <legend><strong>Сменить пароль</strong></legend>
    <form method="post" action="/admin/password">
      <input name="login" placeholder="Логин" required>
      <input name="password" type="text" placeholder="Новый пароль" required>
      <button type="submit">Сменить</button>
    </form>
  </fieldset>

  <fieldset>
    <legend><strong>Публичный сайт (GitHub Pages)</strong></legend>
    <p style="color:var(--muted);font-size:.92rem">Шифрует все страницы новым ключом и
    отправляет на GitHub. После любых изменений пользователей нажмите эту кнопку —
    иначе на публичном сайте изменения не появятся. Публикация занимает несколько секунд,
    сайт обновляется через 1–2 минуты.</p>
    <form method="post" action="/admin/publish">
      <button class="publish" type="submit">Опубликовать на GitHub</button>
    </form>
  </fieldset>
</div>
""" + PAGE_BOTTOM)
        self.send_html(html)

    # --- статика ---

    def serve_static(self, path: str):
        if path == "/":
            path = "/index.html"
        rel = path.lstrip("/")
        if (os.path.basename(rel) in FORBIDDEN
                or ".claude" in rel or rel.startswith(".") or ".." in rel):
            self.send_html("Forbidden", status=403)
            return
        # html-страницы берём из pages/ (открытые исходники), остальное — из корня
        candidates = [os.path.join(PAGES_DIR, rel), os.path.join(BASE_DIR, rel)]
        full = None
        for c in candidates:
            c = os.path.normpath(c)
            if c.startswith(BASE_DIR) and os.path.isfile(c):
                full = c
                break
        if not full:
            if path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_html(PAGE_TOP.format(title="Не найдено", nav="")
                           + '<div class="auth-box"><h1>Страница не найдена</h1>'
                             '<p><a href="/">На главную</a></p></div>'
                           + PAGE_BOTTOM, status=404)
            return
        ext = os.path.splitext(full)[1].lower()
        ctype = STATIC_TYPES.get(ext, "application/octet-stream")
        with open(full, "rb") as f:
            body = f.read()
        if ext == ".html":
            login, user = self.current_user()
            if login:
                extra = ('<a href="/admin">Админ-панель</a>' if user.get("role") == "admin" else "")
                extra += f'<a href="/logout">Выйти ({esc(login)})</a>'
                body = body.replace("</nav>".encode("utf-8"),
                                    (extra + "</nav>").encode("utf-8"), 1)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "publish":
        ok_flag, out = publish_site()
        print(out)
        sys.exit(0 if ok_flag else 1)
    load_users()
    addr = ("0.0.0.0", PORT)
    httpd = http.server.ThreadingHTTPServer(addr, Handler)
    print(f"Портал запущен: http://localhost:{PORT}  (вход по логину и паролю)")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
