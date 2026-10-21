"""A tiny page layout. `page()` inserts `body` as given, so whatever calls it
decides what is escaped."""

from html import escape

CSS = """body{font-family:system-ui,sans-serif;max-width:46rem;margin:0 auto;padding:1rem;line-height:1.5}
header{display:flex;justify-content:space-between;align-items:center;gap:1rem;border-bottom:1px solid #ddd;padding-bottom:.5rem;margin-bottom:1rem}
form{display:grid;gap:.5rem;margin:1rem 0}form.inline{display:inline;margin:0}
input,textarea,button{font:inherit;padding:.4rem}textarea{min-height:6rem}
.card{border:1px solid #ddd;border-radius:.5rem;padding:.75rem;margin:.5rem 0}.muted{color:#666}.error{color:#b00020}"""


def page(title, user, body):
    if user:
        csrf = user["csrf"] if "csrf" in user.keys() and user["csrf"] else ""
        token = f'<input type="hidden" name="csrf" value="{escape(csrf)}">' if csrf else ""
        admin = ' · <a href="/admin">Admin</a>' if user["is_admin"] else ""
        nav = (
            f'{escape(user["name"])} · <a href="/settings">Settings</a>{admin} '
            f'<form method="post" action="/logout" class="inline">{token}<button>Sign out</button></form>'
        )
    else:
        nav = '<a href="/login">Sign in</a> · <a href="/signup">Sign up</a>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(title)} · Pantry</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header><a href="/"><strong>Pantry</strong></a><nav>{nav}</nav></header>
  <main>{body}</main>
</body>
</html>"""
