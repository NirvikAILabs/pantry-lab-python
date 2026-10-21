"""Pantry, fixed: the same app as ../main.py with every lab's fix applied.
Compare the two files to see each change. Run with: python solution/main.py"""

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import os
import re
import secrets
import socket
import sys
import time
import urllib.parse
import urllib.request
from html import escape
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn  # noqa: E402
from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response  # noqa: E402

from db import SCRYPT, db, scrypt_hash, seed, sha256  # noqa: E402
from layout import CSS, page  # noqa: E402

PORT = int(os.environ.get("PORT", "8000"))
# Behind HTTPS in production, cookies must be Secure. Locally we use http.
SECURE_COOKIES = os.environ.get("ENV") == "production"
seed(scrypt_hash)
# Lab: logging. Log events, never form bodies or passwords.
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("pantry")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# Lab: headers. Security headers on every response.
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if SECURE_COOKIES:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ─── Passwords ───────────────────────────────────────────────────────────────
# Lab: passwords. Salted scrypt hashes, checked in constant time. Old unsalted
# SHA-256 hashes still work once, and are upgraded at sign-in.
def verify_password(password: str, stored: str) -> bool:
    parts = stored.split("$")
    if parts[0] != "scrypt":
        return hmac.compare_digest(sha256(password), stored)
    _, salt_hex, key_hex = parts
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), **SCRYPT)
    return hmac.compare_digest(candidate, bytes.fromhex(key_hex))


# A real hash to compare against when the email is unknown, so both cases take as long.
DUMMY_HASH = scrypt_hash(secrets.token_hex(16))

# Lab: passwords. At most 5 failed sign-ins per email and address in 15 minutes.
failures: dict[str, list[float]] = {}
WINDOW = 15 * 60


def too_many_failures(key: str) -> bool:
    recent = [t for t in failures.get(key, []) if time.time() - t < WINDOW]
    failures[key] = recent
    return len(recent) >= 5


# ─── Sessions ────────────────────────────────────────────────────────────────
# Lab: sessions. Random ids, HttpOnly + SameSite cookies, a CSRF token per session.
def current_user(request: Request):
    sid = request.cookies.get("sid")
    if not sid:
        return None
    return db.execute(
        "select users.*, sessions.id as sid, sessions.csrf from sessions join users on users.id = sessions.user_id where sessions.id = ?",
        (sid,),
    ).fetchone()


def sign_in(response: Response, user_id: int):
    sid = secrets.token_urlsafe(32)
    db.execute("insert into sessions (id, user_id, csrf) values (?, ?, ?)", (sid, user_id, secrets.token_urlsafe(32)))
    db.commit()
    response.set_cookie("sid", sid, path="/", httponly=True, samesite="lax", secure=SECURE_COOKIES, max_age=60 * 60 * 24 * 7)


def to(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


# Lab: CSRF. State-changing forms carry the session's token.
def csrf_field(user) -> str:
    return f'<input type="hidden" name="csrf" value="{escape(user["csrf"])}">'


def csrf_ok(form, user) -> bool:
    return hmac.compare_digest(str(form.get("csrf", "")), user["csrf"] or "")


FORBIDDEN = PlainTextResponse("Invalid form token. Reload the page and try again.", status_code=403)


@app.get("/style.css")
def style():
    return Response(CSS, media_type="text/css")


# ─── Home and search ─────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    user = current_user(request)
    recipes = db.execute(
        "select id, title, private from recipes where private = 0 or owner_id = ? order by id",
        (user["id"] if user else 0,),
    ).fetchall()
    # Lab: XSS. Escape everything users wrote.
    items = "".join(
        f'<li><a href="/recipes/{r["id"]}">{escape(r["title"])}</a>{" <span class=muted>(private)</span>" if r["private"] else ""}</li>'
        for r in recipes
    )
    form = (
        f"""<h2>Add a recipe</h2>
        <form method="post" action="/recipes">{csrf_field(user)}
          <input name="title" placeholder="Title" required>
          <textarea name="body" placeholder="Ingredients and steps" required></textarea>
          <label><input type="checkbox" name="private" value="1"> Private (only me)</label>
          <button>Save recipe</button>
        </form>
        <h2>Import a recipe from a web page</h2>
        <form method="post" action="/import">{csrf_field(user)}
          <input name="url" placeholder="https://example.com/recipe" required>
          <button>Import</button>
        </form>"""
        if user
        else ""
    )
    return page(
        "Recipes",
        user,
        f"""<form method="get" action="/search"><input name="q" placeholder="Search public recipes"><button>Search</button></form>
        <h1>Recipes</h1><ul>{items}</ul>{form}""",
    )


@app.get("/search", response_class=HTMLResponse)
def search(request: Request, q: str = ""):
    # Lab: injection. The search text is a parameter, never part of the SQL.
    rows = db.execute(
        "select id, title from recipes where private = 0 and title like '%' || ? || '%'", (q,)
    ).fetchall()
    items = "".join(f'<li><a href="/recipes/{r["id"]}">{escape(r["title"])}</a></li>' for r in rows)
    return page(
        "Search", current_user(request), f"<h1>Results for “{escape(q)}”</h1><ul>{items or '<li>No recipes found.</li>'}</ul>"
    )


# ─── Recipes and comments ────────────────────────────────────────────────────
# Lab: access control. Private recipes are only for their owner; others get
# the same 404 as a missing recipe.
def visible_recipe(recipe_id: str, user):
    recipe = db.execute("select * from recipes where id = ?", (int(recipe_id) if recipe_id.isdigit() else 0,)).fetchone()
    if recipe is None or (recipe["private"] and (user is None or recipe["owner_id"] != user["id"])):
        return None
    return recipe


@app.get("/recipes/{recipe_id}", response_class=HTMLResponse)
def show_recipe(request: Request, recipe_id: str):
    user = current_user(request)
    recipe = visible_recipe(recipe_id, user)
    if recipe is None:
        return HTMLResponse(page("Not found", user, "<h1>Recipe not found</h1>"), status_code=404)
    comments = db.execute(
        "select comments.body, users.name from comments join users on users.id = comments.user_id where recipe_id = ? order by comments.id",
        (recipe["id"],),
    ).fetchall()
    items = "".join(f'<div class="card"><strong>{escape(c["name"])}</strong><p>{escape(c["body"])}</p></div>' for c in comments)
    form = (
        f'<form method="post" action="/recipes/{recipe["id"]}/comments">{csrf_field(user)}<textarea name="body" required></textarea><button>Comment</button></form>'
        if user
        else ""
    )
    return page(recipe["title"], user, f'<h1>{escape(recipe["title"])}</h1><p>{escape(recipe["body"])}</p><h2>Comments</h2>{items}{form}')


@app.post("/recipes")
async def create_recipe(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    form = await request.form()
    if not csrf_ok(form, user):
        return FORBIDDEN
    cur = db.execute(
        "insert into recipes (owner_id, title, body, private) values (?, ?, ?, ?)",
        (user["id"], str(form["title"])[:200], str(form["body"])[:10_000], 1 if form.get("private") else 0),
    )
    db.commit()
    return to(f"/recipes/{cur.lastrowid}")


@app.post("/recipes/{recipe_id}/comments")
async def add_comment(request: Request, recipe_id: str):
    user = current_user(request)
    if not user:
        return to("/login")
    form = await request.form()
    if not csrf_ok(form, user):
        return FORBIDDEN
    recipe = visible_recipe(recipe_id, user)
    if recipe is None:
        return PlainTextResponse("Not found", status_code=404)
    db.execute("insert into comments (recipe_id, user_id, body) values (?, ?, ?)", (recipe["id"], user["id"], str(form["body"])[:2000]))
    db.commit()
    return to(f"/recipes/{recipe['id']}")


# Lab: SSRF. Only public https addresses, no redirects, a timeout and a size cap.
class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_public_page(raw: str):
    url = urllib.parse.urlsplit(raw)
    if url.scheme != "https" or not url.hostname or url.username or url.password:
        return None
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(url.hostname, url.port or 443)}
    except OSError:
        return None
    if not addresses or not all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses):
        return None
    # Note: a determined attacker can change DNS between this check and the
    # request ("DNS rebinding"). Production code pins the checked address, or
    # sends requests through an egress proxy that enforces the same rules.
    opener = urllib.request.build_opener(NoRedirects)
    with opener.open(raw, timeout=5) as response:
        if response.status != 200:
            return None
        return response.read(200_000).decode(errors="replace")


@app.post("/import")
async def import_recipe(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    form = await request.form()
    if not csrf_ok(form, user):
        return FORBIDDEN
    try:
        html = await asyncio.to_thread(fetch_public_page, str(form.get("url", "")))
    except OSError:
        html = None
    if html is None:
        return HTMLResponse(
            page("Import", user, "<h1>That address can’t be imported</h1><p>Use a public https:// page.</p>"), status_code=400
        )
    text = re.sub(r"<[^>]*>", " ", html)[:2000]
    cur = db.execute(
        "insert into recipes (owner_id, title, body, private) values (?, ?, ?, 1)",
        (user["id"], f"Imported from {urllib.parse.urlsplit(str(form['url'])).hostname}", text),
    )
    db.commit()
    return to(f"/recipes/{cur.lastrowid}")


@app.get("/internal/stats")
def internal_stats(request: Request):
    if request.client.host not in ("127.0.0.1", "::1"):
        return PlainTextResponse("Internal only", status_code=403)
    users = db.execute("select count(*) from users").fetchone()[0]
    return {"users": users, "internalApiToken": "pantry-internal-7f3a9c2e", "note": "internal monitoring data"}


# ─── Accounts ────────────────────────────────────────────────────────────────
def account_form(action, label, error=""):
    name = '<input name="name" placeholder="Name" required>' if action == "/signup" else ""
    message = f'<p class="error">{escape(error)}</p>' if error else ""
    return f"""<h1>{label}</h1>{message}
    <form method="post" action="{action}">{name}
      <input name="email" type="email" placeholder="Email" required>
      <input name="password" type="password" placeholder="Password" minlength="15" required>
      <button>{label}</button>
    </form>"""


@app.get("/signup", response_class=HTMLResponse)
def signup_page():
    return page("Sign up", None, account_form("/signup", "Sign up"))


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return page("Sign in", None, account_form("/login", "Sign in"))


@app.post("/signup")
async def signup(request: Request):
    form = await request.form()
    password = str(form.get("password", ""))
    if len(password) < 15:
        return HTMLResponse(page("Sign up", None, account_form("/signup", "Sign up", "Use at least 15 characters.")), status_code=400)
    if db.execute("select 1 from users where email = ?", (form["email"],)).fetchone():
        return HTMLResponse(page("Sign up", None, account_form("/signup", "Sign up", "Could not create that account.")), status_code=400)
    cur = db.execute(
        "insert into users (email, name, password_hash) values (?, ?, ?)",
        (str(form["email"]), str(form["name"])[:100], scrypt_hash(password)),
    )
    db.commit()
    response = to("/")
    sign_in(response, cur.lastrowid)
    return response


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    email = str(form.get("email", "")).lower()
    key = f"{email}|{request.client.host}"
    if too_many_failures(key):
        return HTMLResponse(
            page("Sign in", None, account_form("/login", "Sign in", "Too many attempts. Try again in 15 minutes.")), status_code=429
        )
    user = db.execute("select * from users where lower(email) = ?", (email,)).fetchone()
    password = str(form.get("password", ""))
    ok = verify_password(password, user["password_hash"] if user else DUMMY_HASH) and user is not None
    if not ok:
        failures[key].append(time.time())
        log.warning("event=login_failed")
        # Lab: passwords. The same message whether the email exists or not.
        return HTMLResponse(page("Sign in", None, account_form("/login", "Sign in", "Wrong email or password.")), status_code=401)
    failures.pop(key, None)
    if not user["password_hash"].startswith("scrypt$"):
        db.execute("update users set password_hash = ? where id = ?", (scrypt_hash(password), user["id"]))
        db.commit()
    log.info("event=login user_id=%s", user["id"])
    response = to("/")
    sign_in(response, user["id"])
    return response


@app.post("/logout")
async def logout(request: Request):
    user = current_user(request)
    # Lab: sessions. End the session on the server, not just in the browser.
    if user:
        form = await request.form()
        if not csrf_ok(form, user):
            return FORBIDDEN
        db.execute("delete from sessions where id = ?", (user["sid"],))
        db.commit()
    response = to("/")
    response.delete_cookie("sid", path="/")
    return response


# ─── Settings and admin ──────────────────────────────────────────────────────
@app.get("/settings", response_class=HTMLResponse)
def settings(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    return page(
        "Settings",
        user,
        f"""<h1>Settings</h1><p>Email: {escape(user["email"])}</p>
        <form method="post" action="/settings/email">{csrf_field(user)}<input name="email" type="email" placeholder="New email" required><button>Change email</button></form>""",
    )


# Lab: CSRF. Changes happen only through POST with the session's token.
@app.post("/settings/email")
async def change_email(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    form = await request.form()
    if not csrf_ok(form, user):
        return FORBIDDEN
    db.execute("update users set email = ? where id = ?", (str(form["email"]), user["id"]))
    db.commit()
    log.info("event=email_changed user_id=%s", user["id"])
    return to("/settings")


# Lab: access control. Admin pages check the role, not just sign-in.
@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    if not user["is_admin"]:
        return HTMLResponse(page("Forbidden", user, "<h1>Admins only</h1>"), status_code=403)
    users = db.execute("select id, name, email, is_admin from users order by id").fetchall()
    items = "".join(
        f'<li>{escape(u["name"])} · {escape(u["email"])}{" · admin" if u["is_admin"] else ""}</li>' for u in users
    )
    return page("Admin", user, f"<h1>All users</h1><ul>{items}</ul>")


# Lab: errors. Log the details; show the user a plain message.
@app.exception_handler(Exception)
async def hide_error(request: Request, exc: Exception):
    log.exception("request failed")
    return PlainTextResponse("Something went wrong. Please try again.", status_code=500)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT)
