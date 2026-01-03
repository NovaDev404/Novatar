#!/usr/bin/env python3
"""
Novatar Flask port — no .php endpoints, using proper .html and .png endpoints.

Place Roboto-Regular.ttf in the project root for font rendering.
"""

import os
import re
import json
import hashlib
import tempfile
import time
from pathlib import Path
from io import BytesIO
from urllib.parse import quote
from flask_cors import CORS

from flask import (
    Flask, request, jsonify, session, redirect, url_for, send_file,
    abort, render_template, make_response
)
import requests
import bcrypt
from PIL import Image, ImageDraw, ImageFont

# Configuration
APP_ROOT = Path(__file__).parent.resolve()
USERS_FILE = APP_ROOT / "users.json"
FONT_PATH = APP_ROOT / "Roboto-Regular.ttf"
SECRET_KEY = os.environ.get("NOVATAR_SECRET_KEY", "please-set-a-secure-secret-in-production")

# Flask init
app = Flask(__name__, static_folder=str(APP_ROOT), template_folder=str(APP_ROOT / "templates"))
app.secret_key = SECRET_KEY
CORS(app)


# -------------------------
# Utility functions
# -------------------------
def load_users():
    if not USERS_FILE.exists():
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def save_users_atomic(users):
    fd, tmp = tempfile.mkstemp(dir=str(APP_ROOT))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(users, f, ensure_ascii=False, indent=4)
        os.replace(tmp, str(USERS_FILE))
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


def find_user_entry(users, username):
    if not username:
        return None, None
    search = username.lower()
    # if dict keyed by username
    if isinstance(users, dict):
        for k, v in users.items():
            if k.lower() == search:
                return v, k
    if isinstance(users, list):
        for entry in users:
            if not isinstance(entry, dict):
                continue
            if (entry.get("username_lower") or "").lower() == search:
                return entry, None
            if (entry.get("username") or "").lower() == search:
                return entry, None
            for maybe in ("user", "account"):
                val = entry.get(maybe)
                if isinstance(val, dict) and (val.get("username") or "").lower() == search:
                    return val, None
    if isinstance(users, dict):
        for k, v in users.items():
            if k.lower() == search:
                return v, k
    return None, None


def curl_fetch_bytes(url, timeout=8):
    try:
        headers = {"User-Agent": "Novatar/1.0 (+novatar.novadev.vip)"}
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True)
        if 200 <= r.status_code < 300:
            return r.content, r.headers.get("Content-Type")
    except Exception:
        pass
    return None, None

def color_hex_to_rgb(hex_color: str):
    if not hex_color:
        return (124, 92, 255)
    hex_color = hex_color.strip().lstrip('#')
    if len(hex_color) == 3:
        hex_color = ''.join(c * 2 for c in hex_color)
    try:
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    except:
        return (124, 92, 255)


def create_text_image(text, bg_color="#7c5cff", fg_color="#ffffff", size=512):
    size = max(32, min(2048, int(size)))
    bg_rgb = color_hex_to_rgb(bg_color)
    fg_rgb = color_hex_to_rgb(fg_color)

    img = Image.new("RGBA", (size, size), bg_rgb + (255,))
    draw = ImageDraw.Draw(img)

    text_u = (text or "").upper()
    if text_u == "":
        text_u = "?"

    # Use Roboto if available
    if FONT_PATH.exists():
        font_size = int(size * 0.4)
        try:
            font = ImageFont.truetype(str(FONT_PATH), font_size)
            # measure with textbbox
            bbox = draw.textbbox((0, 0), text_u, font=font)
            text_w = bbox[2] - bbox[0]
            text_h = bbox[3] - bbox[1]

            # Scale font to fit
            while (text_w > size * 0.9 or text_h > size * 0.9) and font_size > 10:
                font_size -= 2
                font = ImageFont.truetype(str(FONT_PATH), font_size)
                bbox = draw.textbbox((0, 0), text_u, font=font)
                text_w = bbox[2] - bbox[0]
                text_h = bbox[3] - bbox[1]

            x = (size - text_w) // 2 - bbox[0]
            y = (size - text_h) // 2 - bbox[1]

            # Draw shadow
            shadow_offset = 2
            draw.text((x + shadow_offset, y + shadow_offset), text_u, font=font, fill=(0, 0, 0, 128))
            draw.text((x, y), text_u, font=font, fill=fg_rgb)
        except Exception as e:
            print(f"Error using custom font: {e}")
            # Fallback to default font
            font = ImageFont.load_default()
            bbox = draw.textbbox((0, 0), text_u, font=font)
            text_w = bbox[2] - bbox[0]
            text_h = bbox[3] - bbox[1]
            x = (size - text_w) // 2 - bbox[0]
            y = (size - text_h) // 2 - bbox[1]
            draw.text((x, y), text_u, font=font, fill=fg_rgb)
    else:
        font = ImageFont.load_default()
        bbox = draw.textbbox((0, 0), text_u, font=font)
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
        x = (size - text_w) // 2 - bbox[0]
        y = (size - text_h) // 2 - bbox[1]
        draw.text((x, y), text_u, font=font, fill=fg_rgb)

    out = BytesIO()
    img.convert("RGB").save(out, format="PNG")
    out.seek(0)
    return out

def bcrypt_check_password(plain_password: str, stored_hash: str) -> bool:
    if not plain_password or not stored_hash:
        return False
    ph = stored_hash
    if ph.startswith("$2y$"):
        ph = "$2b$" + ph[4:]
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), ph.encode("utf-8"))
    except Exception:
        return False


# -------------------------
# Pages
# -------------------------
@app.route("/")
def root():
    return redirect("/index.html")


@app.route("/index.html")
def index_html():
    return render_template("index.html")


@app.route("/login.html")
def login_html():
    return render_template("login.html")


@app.route("/signup.html")
def signup_html():
    return render_template("signup.html")


@app.route("/dashboard.html")
def dashboard_html():
    username = session.get("username")
    if not username:
        return redirect("/login.html")
    users = load_users()
    user, _ = find_user_entry(users, username)
    if not user:
        return "User not found. <a href='/logout'>Logout</a>", 404
    return render_template("dashboard.html", user=user)


# -------------------------
# API (JSON)
# -------------------------
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify(success=False, error="Missing"), 400
    users = load_users()
    found, _ = find_user_entry(users, username)
    if not found:
        return jsonify(success=False, error="Invalid username or password"), 400
    if not bcrypt_check_password(password, found.get("password_hash", "")):
        return jsonify(success=False, error="Invalid username or password"), 400
    session["username"] = found.get("username")
    return jsonify(success=True)


@app.route("/api/signup", methods=["POST"])
def api_signup():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username or not password:
        return jsonify(success=False, error="Missing username or password"), 400
    if not re.match(r'^[A-Za-z0-9_-]+$', username):
        return jsonify(success=False, error="Invalid username characters"), 400
    users = load_users()
    lower = username.lower()
    for u in users:
        if (u.get("username_lower") or "").lower() == lower:
            return jsonify(success=False, error="Username already exists"), 400
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    entry = {
        "username": username,
        "username_lower": lower,
        "password_hash": pw_hash,
        "avatar": {"type": "placeholder"},
        "created_at": int(time.time())
    }
    users.append(entry)
    save_users_atomic(users)
    session["username"] = username
    return jsonify(success=True)


@app.route("/api/save_avatar", methods=["POST"])
def api_save_avatar():
    if "username" not in session:
        return jsonify(success=False, error="Not logged in"), 403
    payload = request.get_json(silent=True) or {}
    source = payload.get("source", "github")
    username = session["username"]
    users = load_users()
    idx = None
    for i, u in enumerate(users):
        if (u.get("username_lower") or "") == username.lower():
            idx = i
            break
    if idx is None:
        return jsonify(success=False, error="User not found"), 404
    avatar = {"type": source}
    if source == "github":
        avatar["gh_username"] = (payload.get("gh") or username).strip()
    elif source == "initials":
        avatar["initials"] = (payload.get("initials") or username[:2].upper()).strip()
        avatar["bg"] = (payload.get("bg") or "#7c5cff").strip()
        avatar["fg"] = (payload.get("fg") or "#ffffff").strip()
    elif source == "url":
        avatar["url"] = (payload.get("url") or "").strip()
    elif source == "gravatar":
        avatar["email"] = (payload.get("email") or "").strip()
    users[idx]["avatar"] = avatar
    save_users_atomic(users)
    return jsonify(success=True)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login.html")


# -------------------------
# Image endpoints (no .php)
# -------------------------
@app.route("/avatar/<username>.png")
def avatar_png(username):
    debug = request.args.get("debug") == "1"
    username = (username or "").strip()
    if debug:
        out_lines = ["Novatar avatar debug", "", f"Requested username: {(username or '(empty)')}"]
    if username == "":
        if debug:
            out_lines.append("No username provided — redirecting to placeholder")
            return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
        return redirect(url_for("placeholder_png"))

    users = load_users()
    found, found_key = find_user_entry(users, username)
    if debug:
        out_lines.append("")
        out_lines.append("Found entry: " + ("YES" if found else "NO"))
        if found:
            out_lines.append("Found raw json snippet:")
            out_lines.append(json.dumps(found, indent=2, ensure_ascii=False))
        else:
            out_lines.append("No matching user found")

    if not found or not isinstance(found, dict):
        if debug:
            out_lines.append("Falling back to placeholder")
            return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
        return redirect(url_for("placeholder_png", initials=username))

    avatar = {}
    if isinstance(found.get("avatar"), dict):
        avatar = found.get("avatar")
    else:
        if "type" in found:
            avatar["type"] = found["type"]
        for k in ("gh_username", "github_username", "github", "gh", "git"):
            if found.get(k):
                avatar["gh_username"] = found.get(k)
                avatar["type"] = avatar.get("type") or "github"
                break
        for k in ("url", "image", "avatar_url", "profile_url"):
            if found.get(k):
                avatar["url"] = found.get(k)
                avatar["type"] = avatar.get("type") or "url"
                break
        for k in ("email", "gravatar_email", "grav_email"):
            if found.get(k):
                avatar["email"] = found.get(k)
                avatar["type"] = avatar.get("type") or "gravatar"
                break
        for k in ("initials",):
            if found.get(k):
                avatar["initials"] = found.get(k)
                avatar["bg"] = found.get("bg") or "#7c5cff"
                avatar["fg"] = found.get("fg") or "#ffffff"
                avatar["type"] = avatar.get("type") or "initials"
                break

    t = (avatar.get("type") or "github").lower().strip()

    def try_fetch_and_send(url, timeout=8):
        data, ct = curl_fetch_bytes(url, timeout=timeout)
        if data:
            return send_file(BytesIO(data), mimetype=(ct or "image/png"))
        return None

    if t == "github":
        gh = avatar.get("gh_username") or found.get("username") or found.get("user") or ""
        m = re.search(r"https?://github\.com/([^/?#]+)", gh or "", flags=re.I)
        if m:
            gh = m.group(1)
        gh = gh.strip()
        if not gh:
            if debug:
                out_lines.append("No GH username")
                return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
            return redirect(url_for("placeholder_png", initials=username))
        url = f"https://github.com/{quote(gh)}.png"
        r = try_fetch_and_send(url, timeout=8)
        if r:
            return r
        if debug:
            out_lines.append("Failed to fetch GitHub image — fallback")
            return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
        return redirect(url_for("placeholder_png", initials=username))

    if t == "url":
        imgurl = avatar.get("url") or ""
        if not re.match(r"^https?://", imgurl or "", flags=re.I):
            if debug:
                out_lines.append("Invalid image URL")
                return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
            return redirect(url_for("placeholder_png", initials=username))
        r = try_fetch_and_send(imgurl, timeout=8)
        if r:
            return r
        if debug:
            out_lines.append("Failed to fetch URL image — fallback")
            return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
        return redirect(url_for("placeholder_png", initials=username))

    if t == "gravatar":
        email = (avatar.get("email") or "").strip().lower()
        if not email:
            if debug:
                out_lines.append("No gravatar email")
                return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
            return redirect(url_for("placeholder_png", initials=username))
        h = hashlib.md5(email.encode("utf-8")).hexdigest()
        size = 512
        url = f"https://www.gravatar.com/avatar/{h}?s={size}&d=identicon"
        r = try_fetch_and_send(url, timeout=8)
        if r:
            return r
        if debug:
            out_lines.append("Failed to fetch gravatar — fallback")
            return "\n".join(out_lines), 200, {"Content-Type": "text/plain; charset=utf-8"}
        return redirect(url_for("placeholder_png", initials=username))

    if t == "initials":
        initials = str(avatar.get("initials") or username[:2].upper())
        bg = str(avatar.get("bg") or "#7c5cff")
        fg = str(avatar.get("fg") or "#ffffff")
        out = create_text_image(initials, bg, fg, size=512)
        return send_file(out, mimetype="image/png")

    return redirect(url_for("placeholder_png", initials=username))


@app.route("/preview.png")
def preview_png():
    t = (request.args.get("type") or "").strip()
    size = int(request.args.get("size") or 512)
    size = max(32, min(2048, size))

    def fetch_bytes(url, timeout=6):
        return curl_fetch_bytes(url, timeout=timeout)

    if t == "initials":
        initials = request.args.get("initials") or "AB"
        bg = request.args.get("bg") or "#7c5cff"
        fg = request.args.get("fg") or "#ffffff"
        out = create_text_image(initials, bg, fg, size=size)
        return send_file(out, mimetype="image/png")

    if t == "gravatar":
        email = (request.args.get("email") or "").strip().lower()
        h = hashlib.md5(email.encode("utf-8")).hexdigest()
        s = max(32, min(2048, int(request.args.get("size") or size)))
        url = f"https://www.gravatar.com/avatar/{h}?s={s}&d=identicon"
        data, ct = fetch_bytes(url, timeout=6)
        if data:
            return send_file(BytesIO(data), mimetype=(ct or "image/png"))
        return redirect(url_for("placeholder_png", initials=email[:2]))

    if t == "github":
        gh = (request.args.get("gh") or "preview")
        return redirect(f"https://github.com/{quote(gh)}.png")

    if t == "url":
        u = request.args.get("u") or ""
        if not re.match(r"^https?://", u or "", flags=re.I):
            return redirect(url_for("placeholder_png"))
        data, ct = curl_fetch_bytes(u, timeout=6)
        if data:
            return send_file(BytesIO(data), mimetype=(ct or "application/octet-stream"))
        return redirect(url_for("placeholder_png"))

    return redirect(url_for("placeholder_png"))


@app.route("/placeholder.png")
def placeholder_png():
    initials = (request.args.get("initials") or "").strip()[:2].upper()
    size = max(32, min(2048, int(request.args.get("size") or 512)))
    bg = request.args.get("bg") or "#182026"
    fg = request.args.get("fg") or "#9FB0FF"
    out = create_text_image(initials or "?", bg, fg, size=size)
    return send_file(out, mimetype="image/png")

@app.route("/docs/")
def docs():
    return render_template("docs.html")