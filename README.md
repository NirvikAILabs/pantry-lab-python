# Pantry lab (Python and FastAPI)

Pantry is a small recipe-sharing app with **deliberate security flaws**. It's the lab app for the free course
[Security Fundamentals for Builders](https://ready.nirvik.ai/c/security-fundamentals) on Nirvik Ready.

> **Run it only on your own machine or in your own Codespace. Never deploy it.** It's vulnerable on purpose.

## Start

**In your browser:** click **Code → Codespaces → Create codespace**. When it opens, run `python main.py` in the terminal.

**On your machine:** you need Python 3.11 or newer.

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Then open http://127.0.0.1:8000. Sample accounts:

| Email             | Password          | Role   |
| ----------------- | ----------------- | ------ |
| alice@pantry.test | alice-pantry-2026 | admin  |
| bob@pantry.test   | bob-pantry-2026   | member |

## The labs

Each lesson's lab asks you to find a flaw, try it on your own copy, fix it in `main.py`, and check your fix:

| Lab                         | Flaw                                                                                               |
| --------------------------- | -------------------------------------------------------------------------------------------------- |
| Passwords                   | Unsalted SHA-256 hashes, no limit on guesses, messages that reveal which emails exist              |
| Sessions                    | Guessable session ids, cookies without HttpOnly or SameSite, sign-out that doesn't end the session |
| Access control              | Anyone can read private recipes by changing the id; any user can open the admin page               |
| Injection                   | Search builds SQL from the search text                                                             |
| XSS                         | Comments are shown as HTML; no Content-Security-Policy                                             |
| CSRF and SSRF               | A link can change your email; recipe import fetches any address, including internal ones           |
| Headers, errors and logging | No security headers; stack traces shown to users; passwords written to the log                     |

## Check your fixes

With the app running, in a second terminal:

```bash
python check.py
```

It tries each flaw against your running app and reports which are fixed. The fully fixed app is in
`solution/` (`python solution/main.py`): compare it with your version.

To start again with fresh sample data, stop the app and run `python reset.py`.

## License

MIT. Made by Nirvik AI Labs for learning. Don't reuse this code in real apps: use the solution's ideas instead.
