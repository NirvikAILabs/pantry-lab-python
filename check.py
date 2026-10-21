"""Checks the running Pantry app for each lab's flaw and reports which are
fixed. Start the app first (python main.py), then run: python check.py
Optional: python check.py http://127.0.0.1:8000"""

import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from itertools import groupby

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


opener = urllib.request.build_opener(NoRedirects)


class Client:
    """A tiny client that keeps its own cookie, like one browser tab."""

    def __init__(self):
        self.sid = None

    def request(self, path, method="GET", form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        req = urllib.request.Request(BASE + path, data=data, method=method)
        if self.sid:
            req.add_header("Cookie", f"sid={self.sid}")
        if data is not None:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            res = opener.open(req, timeout=30)
        except urllib.error.HTTPError as error:
            res = error
        set_cookie = ", ".join(res.headers.get_all("set-cookie") or [])
        match = re.search(r"sid=([^;]*)", set_cookie)
        if match:
            self.sid = match.group(1).strip('"') or None
        return res.status, res.headers, set_cookie, res.read().decode(errors="replace")


def csrf_of(html):
    match = re.search(r'name="csrf" value="([^"]*)"', html)
    return match.group(1) if match else ""


def sign_in(email, password):
    client = Client()
    client.request("/login", "POST", {"email": email, "password": password})
    return client


results = []


def check(lab, name):
    def run(test):
        try:
            results.append((lab, name, "fixed" if test() else "VULNERABLE"))
        except Exception as error:  # report and keep going
            results.append((lab, name, f"error: {error}"))

    return run


bob = sign_in("bob@pantry.test", "bob-pantry-2026")
if not bob.sid:
    sys.exit(f"Could not sign in as bob@pantry.test at {BASE}. Is the app running? Try python reset.py.")


def error_message(html):
    match = re.search(r'class="error">([^<]*)<', html)
    return match.group(1) if match else None


@check("Passwords", "Same message for unknown emails and wrong passwords")
def _():
    unknown = Client().request("/login", "POST", {"email": "nobody@pantry.test", "password": "x"})
    wrong = Client().request("/login", "POST", {"email": "bob@pantry.test", "password": "x"})
    return error_message(unknown[3]) == error_message(wrong[3])


@check("Sessions", "Session cookie is HttpOnly and SameSite")
def _():
    _, _, cookie, _ = Client().request("/login", "POST", {"email": "bob@pantry.test", "password": "bob-pantry-2026"})
    return bool(re.search("httponly", cookie, re.I) and re.search("samesite=(lax|strict)", cookie, re.I))


@check("Sessions", "Session ids are long and random")
def _():
    return len(bob.sid or "") >= 32


@check("Sessions", "Signing out ends the session on the server")
def _():
    client = sign_in("bob@pantry.test", "bob-pantry-2026")
    old = client.sid
    home = client.request("/")
    client.request("/logout", "POST", {"csrf": csrf_of(home[3])})
    client.sid = old
    return client.request("/settings")[0] != 200


@check("Access control", "Bob can’t read Alice’s private recipe")
def _():
    status, _, _, text = bob.request("/recipes/1")
    return status == 404 and "garam masala" not in text


@check("Access control", "Bob can’t open the admin page")
def _():
    return bob.request("/admin")[0] in (403, 404)


@check("Injection", "Search can’t be turned into a query for user emails")
def _():
    q = urllib.parse.quote("' union select id, email from users --")
    return "alice@pantry.test" not in bob.request(f"/search?q={q}")[3]


@check("XSS", "Comments are shown as text, not run as code")
def _():
    marker = f"<script>alert('xss-{time.time()}')</script>"
    page = bob.request("/recipes/3")[3]
    bob.request("/recipes/3/comments", "POST", {"body": marker, "csrf": csrf_of(page)})
    return marker not in bob.request("/recipes/3")[3]


@check("XSS", "A Content-Security-Policy header is set")
def _():
    return "script-src" in (bob.request("/")[1].get("content-security-policy") or "")


@check("CSRF", "A link can’t change Bob’s email")
def _():
    bob.request("/settings/email?email=attacker%40evil.test")
    changed = "attacker@evil.test" in bob.request("/settings")[3]
    if changed:
        bob.request("/settings/email?email=bob%40pantry.test")
    return not changed


@check("CSRF", "A form post without the token is refused")
def _():
    status = bob.request("/settings/email", "POST", {"email": "attacker@evil.test"})[0]
    return status == 403 and "attacker@evil.test" not in bob.request("/settings")[3]


@check("SSRF", "Import can’t reach internal addresses")
def _():
    home = bob.request("/")[3]
    port = urllib.parse.urlsplit(BASE).port or 80
    status, headers, _, text = bob.request(
        "/import", "POST", {"url": f"http://127.0.0.1:{port}/internal/stats", "csrf": csrf_of(home)}
    )
    if 300 <= status < 400:
        text = bob.request(headers["location"])[3]
    return "pantry-internal" not in text


@check("Headers and errors", "X-Content-Type-Options: nosniff is set")
def _():
    return bob.request("/")[1].get("x-content-type-options") == "nosniff"


@check("Headers and errors", "Errors don’t show stack traces")
def _():
    text = bob.request("/recipes/999999")[3]
    return "Traceback" not in text and "Error:" not in text


# Last, because it may lock out its test address for 15 minutes.
@check("Passwords", "Repeated failed sign-ins are slowed down")
def _():
    email = f"ratelimit-{time.time()}@pantry.test"
    for i in range(8):
        if Client().request("/login", "POST", {"email": email, "password": f"guess-{i}"})[0] == 429:
            return True
    return False


width = max(len(r[1]) for r in results)
order = list(dict.fromkeys(r[0] for r in results))
for lab, rows in groupby(sorted(results, key=lambda r: order.index(r[0])), key=lambda r: r[0]):
    print(f"\n{lab}")
    for _, name, status in rows:
        print(f"  {'✓' if status == 'fixed' else '✗'} {name.ljust(width)}  {status}")
fixed = sum(1 for r in results if r[2] == "fixed")
print(f"\n{fixed} of {len(results)} checks pass.")
