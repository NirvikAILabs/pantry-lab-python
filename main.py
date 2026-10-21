"""Pantry: a small recipe-sharing app with deliberate security flaws, for the
labs of Security Fundamentals for Builders (Nirvik Ready). Run it only on your
own machine: never deploy it. The fixed version is in solution/."""

import asyncio
import logging
import os
import re
import traceback
import urllib.request

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from db import db, seed, sha256
from layout import CSS, page

PORT = int(os.environ.get("PORT", "8000"))
seed(sha256)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("pantry")
app = FastAPI()

# ─── Sessions ────────────────────────────────────────────────────────────────
next_session = db.execute("select count(*) from sessions").fetchone()[0] + 1


def current_user(request: Request):
    sid = request.cookies.get("sid")
    if not sid:
        return None
    return db.execute(
        "select users.* from sessions join users on users.id = sessions.user_id where sessions.id = ?", (sid,)
    ).fetchone()


def sign_in(response: Response, user_id: int):
    global next_session
    sid = str(next_session)
    next_session += 1
    db.execute("insert into sessions (id, user_id) values (?, ?)", (sid, user_id))
    db.commit()
    response.set_cookie("sid", sid, path="/", samesite=None)


def to(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


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
    items = "".join(
        f'<li><a href="/recipes/{r["id"]}">{r["title"]}</a>{" <span class=muted>(private)</span>" if r["private"] else ""}</li>'
        for r in recipes
    )
    form = (
        """<h2>Add a recipe</h2>
        <form method="post" action="/recipes">
          <input name="title" placeholder="Title" required>
          <textarea name="body" placeholder="Ingredients and steps" required></textarea>
          <label><input type="checkbox" name="private" value="1"> Private (only me)</label>
          <button>Save recipe</button>
        </form>
        <h2>Import a recipe from a web page</h2>
        <form method="post" action="/import">
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
    rows = db.execute(f"select id, title from recipes where private = 0 and title like '%{q}%'").fetchall()
    items = "".join(f'<li><a href="/recipes/{r["id"]}">{r["title"]}</a></li>' for r in rows)
    return page("Search", current_user(request), f"<h1>Results for “{q}”</h1><ul>{items or '<li>No recipes found.</li>'}</ul>")


# ─── Recipes and comments ────────────────────────────────────────────────────
@app.get("/recipes/{recipe_id}", response_class=HTMLResponse)
def show_recipe(request: Request, recipe_id: str):
    user = current_user(request)
    recipe = db.execute("select * from recipes where id = ?", (recipe_id,)).fetchone()
    if recipe is None:
        raise LookupError(f"Recipe {recipe_id} not found in table recipes")
    comments = db.execute(
        "select comments.body, users.name from comments join users on users.id = comments.user_id where recipe_id = ? order by comments.id",
        (recipe["id"],),
    ).fetchall()
    items = "".join(f'<div class="card"><strong>{c["name"]}</strong><p>{c["body"]}</p></div>' for c in comments)
    form = (
        f'<form method="post" action="/recipes/{recipe["id"]}/comments"><textarea name="body" required></textarea><button>Comment</button></form>'
        if user
        else ""
    )
    return page(recipe["title"], user, f'<h1>{recipe["title"]}</h1><p>{recipe["body"]}</p><h2>Comments</h2>{items}{form}')


@app.post("/recipes")
async def create_recipe(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    form = await request.form()
    cur = db.execute(
        "insert into recipes (owner_id, title, body, private) values (?, ?, ?, ?)",
        (user["id"], form["title"], form["body"], 1 if form.get("private") else 0),
    )
    db.commit()
    return to(f"/recipes/{cur.lastrowid}")


@app.post("/recipes/{recipe_id}/comments")
async def add_comment(request: Request, recipe_id: str):
    user = current_user(request)
    if not user:
        return to("/login")
    form = await request.form()
    db.execute("insert into comments (recipe_id, user_id, body) values (?, ?, ?)", (recipe_id, user["id"], form["body"]))
    db.commit()
    return to(f"/recipes/{recipe_id}")


def fetch_page(url):
    with urllib.request.urlopen(url) as response:
        return response.read().decode(errors="replace")


# Imports a recipe from a web page: fetches the URL and saves the text.
@app.post("/import")
async def import_recipe(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    form = await request.form()
    html = await asyncio.to_thread(fetch_page, form["url"])
    text = re.sub(r"<[^>]*>", " ", html)[:2000]
    cur = db.execute(
        "insert into recipes (owner_id, title, body, private) values (?, ?, ?, 1)",
        (user["id"], f'Imported from {form["url"]}', text),
    )
    db.commit()
    return to(f"/recipes/{cur.lastrowid}")


# Internal statistics, for the team's monitoring only. Requests from outside
# this machine are refused.
@app.get("/internal/stats")
def internal_stats(request: Request):
    if request.client.host not in ("127.0.0.1", "::1"):
        return PlainTextResponse("Internal only", status_code=403)
    users = db.execute("select count(*) from users").fetchone()[0]
    return {"users": users, "internalApiToken": "pantry-internal-7f3a9c2e", "note": "internal monitoring data"}


# ─── Accounts ────────────────────────────────────────────────────────────────
def account_form(action, label, error=""):
    name = '<input name="name" placeholder="Name" required>' if action == "/signup" else ""
    message = f'<p class="error">{error}</p>' if error else ""
    return f"""<h1>{label}</h1>{message}
    <form method="post" action="{action}">{name}
      <input name="email" type="email" placeholder="Email" required>
      <input name="password" type="password" placeholder="Password" required>
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
    log.info("signup: %s", dict(form))
    cur = db.execute(
        "insert into users (email, name, password_hash) values (?, ?, ?)",
        (form["email"], form["name"], sha256(form["password"])),
    )
    db.commit()
    response = to("/")
    sign_in(response, cur.lastrowid)
    return response


@app.post("/login")
async def login(request: Request):
    form = await request.form()
    log.info("login attempt: %s", dict(form))
    user = db.execute("select * from users where email = ?", (form["email"],)).fetchone()
    if user is None:
        return HTMLResponse(page("Sign in", None, account_form("/login", "Sign in", "No account with that email.")))
    if user["password_hash"] != sha256(form["password"]):
        return HTMLResponse(page("Sign in", None, account_form("/login", "Sign in", "Wrong password.")))
    response = to("/")
    sign_in(response, user["id"])
    return response


@app.post("/logout")
def logout():
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
        f"""<h1>Settings</h1><p>Email: {user["email"]}</p>
        <form method="get" action="/settings/email"><input name="email" type="email" placeholder="New email" required><button>Change email</button></form>""",
    )


@app.get("/settings/email")
def change_email(request: Request, email: str):
    user = current_user(request)
    if not user:
        return to("/login")
    db.execute("update users set email = ? where id = ?", (email, user["id"]))
    db.commit()
    return to("/settings")


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    user = current_user(request)
    if not user:
        return to("/login")
    users = db.execute("select id, name, email, is_admin from users order by id").fetchall()
    items = "".join(f'<li>{u["name"]} · {u["email"]}{" · admin" if u["is_admin"] else ""}</li>' for u in users)
    return page("Admin", user, f"<h1>All users</h1><ul>{items}</ul>")


# Errors: show the details, which helps while developing.
@app.exception_handler(Exception)
async def show_error(request: Request, exc: Exception):
    return PlainTextResponse(f"Error: {exc}\n\n{traceback.format_exc()}", status_code=500)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=PORT)
