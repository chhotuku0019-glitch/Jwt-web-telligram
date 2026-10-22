import os
import json
import time
import hmac
import hashlib
import requests
import asyncio
import threading
import io
from datetime import datetime
from urllib.parse import parse_qsl
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from telegram import (
    Update, 
    ReplyKeyboardMarkup, 
    KeyboardButton, 
    InlineKeyboardMarkup, 
    InlineKeyboardButton, 
    WebAppInfo, 
    MenuButtonWebApp
)
from telegram.ext import (
    ApplicationBuilder, 
    ContextTypes, 
    CommandHandler, 
    CallbackQueryHandler, 
    MessageHandler, 
    filters
)

app = Flask(__name__, template_folder='.')

# Default Configuration — Generic with NO hardcoded tokens or secrets
DEFAULT_CONFIG = {
    "bot_token": "",
    "owner_telegram_id": None,
    "uid_pass_api_url": "https://ff-jwt-gen-api.lovable.app/api/public/token",
    "access_token_api_url": "https://ff-jwt-gen-api.lovable.app/api/public/token",
    "servers": ["IND", "BD", "BR", "NA", "SG"],
    "github_token": "",
    "github_repo": "",
    "github_branch": "main",
    "github_paths": {"IND": "tokens_ind.json", "BD": "tokens_bd.json", "BR": "tokens_br.json"},
    "timer_interval_hours": 6,
    "like_api_url": "https://example.com/like-api-service",
    "admin_password_hash": generate_password_hash("admin123"),
    "mongo_uri": os.environ.get("MONGO_URI", "mongodb://localhost:27017/telegram_bot_db"),
    "miniapp_url": "https://jwt-web-telligram.onrender.com/"
}

# In-memory / MongoDB wrapper state
DB_CLIENT = None
DB = None
USE_MONGO = False

try:
    from pymongo import MongoClient
    mongo_uri = DEFAULT_CONFIG["mongo_uri"]
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=1500)
    client.admin.command('ping')
    DB_CLIENT = client
    DB = client.telegram_bot_db
    USE_MONGO = True
    print("Connected to MongoDB successfully.")
except Exception as e:
    print(f"MongoDB connection notice ({e}), using local JSON file store (local_db.json).")
    USE_MONGO = False

FALLBACK_DB_FILE = "local_db.json"
RECENT_LOGS = []

def add_log(msg: str):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {msg}"
    RECENT_LOGS.append(entry)
    if len(RECENT_LOGS) > 100:
        RECENT_LOGS.pop(0)
    print(entry)

def load_local_db():
    if not os.path.exists(FALLBACK_DB_FILE):
        initial = {"config": DEFAULT_CONFIG, "entries": []}
        with open(FALLBACK_DB_FILE, "w") as f:
            json.dump(initial, f, indent=2)
        return initial
    try:
        with open(FALLBACK_DB_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {"config": DEFAULT_CONFIG, "entries": []}

def save_local_db(data):
    with open(FALLBACK_DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_config():
    if USE_MONGO:
        try:
            cfg = DB.config.find_one({"_id": "settings"})
            if not cfg:
                cfg = DEFAULT_CONFIG.copy()
                cfg["_id"] = "settings"
                DB.config.insert_one(cfg)
            return cfg
        except Exception:
            pass
    ldb = load_local_db()
    return ldb.get("config", DEFAULT_CONFIG)

def update_config(new_config):
    if USE_MONGO:
        try:
            new_config["_id"] = "settings"
            DB.config.replace_one({"_id": "settings"}, new_config, upsert=True)
            return
        except Exception:
            pass
    ldb = load_local_db()
    ldb["config"] = new_config
    save_local_db(ldb)

def get_all_entries():
    if USE_MONGO:
        try:
            return list(DB.entries.find({}, {"_id": 0}))
        except Exception:
            pass
    ldb = load_local_db()
    return ldb.get("entries", [])

def save_entry_db(entry):
    if USE_MONGO:
        try:
            # Query by account_id, or uid, or access_token
            query = {}
            if entry.get("account_id"):
                query = {"account_id": entry["account_id"]}
            elif entry.get("type") == "uid_pass" and entry.get("uid"):
                query = {"uid": entry["uid"]}
            elif entry.get("type") == "access_token" and entry.get("access_token"):
                query = {"access_token": entry["access_token"]}
            if query:
                DB.entries.update_one(query, {"$set": entry}, upsert=True)
            return
        except Exception:
            pass
    ldb = load_local_db()
    entries = ldb.get("entries", [])
    updated = False
    for i, e in enumerate(entries):
        match = False
        if entry.get("account_id") and e.get("account_id") == entry["account_id"]:
            match = True
        elif entry.get("type") == "uid_pass" and entry.get("uid") and e.get("uid") == entry["uid"]:
            match = True
        elif entry.get("type") == "access_token" and entry.get("access_token") and e.get("access_token") == entry["access_token"]:
            match = True
        if match:
            entries[i] = entry
            updated = True
            break
    if not updated:
        entries.append(entry)
    ldb["entries"] = entries
    save_local_db(ldb)

def delete_entry_db(account_id):
    if USE_MONGO:
        try:
            DB.entries.delete_one({"account_id": account_id})
            return
        except Exception:
            pass
    ldb = load_local_db()
    ldb["entries"] = [e for e in ldb.get("entries", []) if e.get("account_id") != account_id]
    save_local_db(ldb)

# Small-caps Unicode translation — Every text, UID, token, or link sent by bot uses this
def to_small_caps(text: str) -> str:
    if not text:
        return ""
    normal = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    small = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢ"
    trans = str.maketrans(normal, small)
    return str(text).translate(trans)

# Mask token helper
def mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 8:
        return "••••••••"
    return "••••••••" + token[-4:]

# Button helpers with Bot API button "style" support
# Supports: "primary" (blue), "success" (green), "danger" (red)
def make_reply_button(text: str, style: str = None) -> KeyboardButton:
    kwargs = {}
    if style:
        kwargs['api_kwargs'] = {'style': style}
    return KeyboardButton(text=text, **kwargs)

def make_inline_button(text: str, callback_data: str = None, web_app: WebAppInfo = None, style: str = None) -> InlineKeyboardButton:
    kwargs = {}
    if callback_data:
        kwargs['callback_data'] = callback_data
    if web_app:
        kwargs['web_app'] = web_app
    if style:
        kwargs['api_kwargs'] = {'style': style}
    return InlineKeyboardButton(text=text, **kwargs)

# Forward message to Admin/Owner
def notify_owner(message_text: str):
    config = get_config()
    owner_id = config.get('owner_telegram_id')
    bot_token = config.get('bot_token')
    if owner_id and bot_token:
        try:
            requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": owner_id, "text": to_small_caps(message_text)},
                timeout=10
            )
        except Exception as e:
            add_log(f"Owner notification error: {e}")

# Forward document file to Admin/Owner
def send_owner_document(file_name: str, file_content: str, caption: str):
    config = get_config()
    owner_id = config.get('owner_telegram_id')
    bot_token = config.get('bot_token')
    if owner_id and bot_token:
        try:
            url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
            files = {"document": (file_name, io.BytesIO(file_content.encode('utf-8')), "application/json")}
            data = {"chat_id": owner_id, "caption": to_small_caps(caption)}
            requests.post(url, data=data, files=files, timeout=15)
        except Exception as e:
            add_log(f"Owner file send error ({file_name}): {e}")

# --- Deduplication & Submission Processing Engine ---
# Rules:
# 1. Single: call JWT API once, verify, save, and forward fresh token to owner immediately.
# 2. Bulk: do NOT call JWT API at submit time. Validate structure, save directly to DB as-is (timer refreshes them later).
# 3. Dedupe:
#    - If same UID already exists in uid_pass entries, skip duplicate (keep first/existing).
#    - If same access_token already exists in access_token entries, skip duplicate.
#    - If account_id already exists as access_token and new uid_pass submitted, delete access_token (uid_pass wins).
def process_submission(telegram_id, server, submission_type, raw_data_list, is_bulk=False):
    config = get_config()
    added_count = 0
    dup_count = 0
    invalid_count = 0
    results = []
    all_entries = get_all_entries()

    for item in raw_data_list:
        account_id = None
        jwt_token = None
        region = server

        if submission_type == 'uid_pass':
            uid = str(item.get('uid') or "").strip()
            password = str(item.get('password') or "").strip()
            if not uid or not password:
                invalid_count += 1
                continue

            # Dedupe rule: Same UID within uid_pass entries
            existing_uid = next((e for e in all_entries if e.get('type') == 'uid_pass' and str(e.get('uid') or '').strip() == uid), None)
            if existing_uid:
                dup_count += 1
                continue

            if not is_bulk:
                # SINGLE submission: Call JWT API ONCE to verify
                api_url = f"{config['uid_pass_api_url']}?uid={uid}&password={password}"
                try:
                    res = requests.get(api_url, timeout=12)
                    data = res.json()
                    if data.get('success') or data.get('token') or data.get('account_id'):
                        account_id = str(data.get('account_id') or data.get('uid') or uid)
                        jwt_token = data.get('token') or data.get('token_access')
                        region = data.get('region', server)
                    else:
                        invalid_count += 1
                        continue
                except Exception as e:
                    add_log(f"Single JWT API error for UID {uid}: {e}")
                    invalid_count += 1
                    continue
            else:
                # BULK submission: Do NOT call JWT API now. Save directly as unverified
                account_id = uid
                jwt_token = None

        elif submission_type == 'access_token':
            acc_token = str(item.get('access_token') or "").strip()
            if not acc_token:
                invalid_count += 1
                continue

            # Dedupe rule: Same access_token string within access_token entries
            existing_token = next((e for e in all_entries if e.get('type') == 'access_token' and str(e.get('access_token') or '').strip() == acc_token), None)
            if existing_token:
                dup_count += 1
                continue

            if not is_bulk:
                # SINGLE submission: Call JWT API ONCE to verify
                api_url = f"{config['access_token_api_url']}?access_token={acc_token}"
                try:
                    res = requests.get(api_url, timeout=12)
                    data = res.json()
                    account_id = str(
                        data.get('account_id') or 
                        data.get('account_uid') or 
                        data.get('Uid') or 
                        data.get('jwt_decoded', {}).get('payload', {}).get('account_id') or 
                        ""
                    )
                    jwt_token = data.get('token')
                    region = data.get('region', server)
                    if not account_id or not jwt_token:
                        invalid_count += 1
                        continue
                except Exception as e:
                    add_log(f"Single Token API error: {e}")
                    invalid_count += 1
                    continue
            else:
                # BULK submission: Do NOT call JWT API now.
                account_id = hashlib.sha256(acc_token.encode('utf-8')).hexdigest()[:16]
                jwt_token = None

        # Cross-type dedupe rule: if account_id already exists as access_token, uid_pass wins
        if account_id:
            existing_acc = next((e for e in all_entries if e.get('account_id') == account_id), None)
            if existing_acc:
                if submission_type == 'uid_pass' and existing_acc.get('type') == 'access_token':
                    delete_entry_db(account_id)
                    all_entries = [e for e in all_entries if e.get('account_id') != account_id]
                elif existing_acc.get('type') == submission_type:
                    dup_count += 1
                    continue

        entry = {
            "telegram_id": int(telegram_id),
            "server": server,
            "type": submission_type,
            "uid": item.get('uid'),
            "password": item.get('password'),
            "access_token": item.get('access_token'),
            "account_id": account_id,
            "token": jwt_token,
            "region": region,
            "timestamp": datetime.utcnow().isoformat()
        }
        save_entry_db(entry)
        all_entries.append(entry)
        added_count += 1
        results.append(entry)

        # Requirement 5: Whenever a brand-new token is generated for any entry (single verified submission),
        # forward that fresh token to the admin/owner immediately
        if not is_bulk and jwt_token:
            fresh_alert = f"ꜰʀᴇꜱʜ ᴛᴏᴋᴇɴ ɢᴇɴᴇʀᴀᴛᴇᴅ:\nꜱᴇʀᴠᴇʀ: {server}\nᴜɪᴅ: {entry.get('uid') or entry.get('account_id')}\nᴛᴏᴋᴇɴ: {jwt_token}"
            notify_owner(fresh_alert)

    return {"added": added_count, "duplicate": dup_count, "invalid": invalid_count, "results": results}

# --- Background Timer: Token Refresh, Split Reports, & GitHub Sync ---
def background_timer_job():
    add_log("Starting scheduled background token refresh & GitHub sync...")
    config = get_config()
    entries = get_all_entries()
    
    succeeded_entries = []
    failed_entries = []
    
    for entry in entries:
        token_success = False
        new_token = None
        acc_id = entry.get('account_id')
        
        try:
            if entry.get('type') == 'uid_pass' and entry.get('uid') and entry.get('password'):
                api_url = f"{config['uid_pass_api_url']}?uid={entry['uid']}&password={entry['password']}"
                res = requests.get(api_url, timeout=12)
                data = res.json()
                new_token = data.get('token') or data.get('token_access')
                if new_token:
                    entry['token'] = new_token
                    if data.get('account_id'):
                        entry['account_id'] = str(data.get('account_id'))
                    save_entry_db(entry)
                    token_success = True
                    succeeded_entries.append({
                        "uid": entry.get('uid'),
                        "account_id": entry.get('account_id'),
                        "server": entry.get('server'),
                        "token": new_token,
                        "type": "uid_pass"
                    })
            elif entry.get('type') == 'access_token' and entry.get('access_token'):
                api_url = f"{config['access_token_api_url']}?access_token={entry['access_token']}"
                res = requests.get(api_url, timeout=12)
                data = res.json()
                new_token = data.get('token')
                if new_token:
                    entry['token'] = new_token
                    resolved_id = str(
                        data.get('account_id') or 
                        data.get('account_uid') or 
                        data.get('jwt_decoded', {}).get('payload', {}).get('account_id') or 
                        acc_id
                    )
                    entry['account_id'] = resolved_id
                    save_entry_db(entry)
                    token_success = True
                    succeeded_entries.append({
                        "account_id": entry.get('account_id'),
                        "server": entry.get('server'),
                        "token": new_token,
                        "type": "access_token"
                    })
            time.sleep(0.4) # Avoid rate limits
        except Exception as e:
            add_log(f"Token refresh failed for account {acc_id}: {e}")

        if not token_success:
            failed_entries.append({
                "uid": entry.get('uid'),
                "account_id": entry.get('account_id'),
                "server": entry.get('server'),
                "type": entry.get('type'),
                "error": "Token regeneration failed or invalid response"
            })

    # GitHub Sync: ONLY update with SUCCEEDED entries (per server)
    updated_servers = []
    if config.get('github_token') and config.get('github_repo'):
        servers = config.get('servers', [])
        github_paths = config.get('github_paths', {})
        
        for server in servers:
            path = github_paths.get(server)
            if not path:
                continue
            server_tokens = [
                {"uid": e.get('uid') or e.get('account_id'), "token": e.get('token')}
                for e in succeeded_entries if e.get('server') == server and e.get('token')
            ]
            if not server_tokens:
                continue

            file_json_str = json.dumps(server_tokens, indent=2)
            try:
                repo = config['github_repo']
                branch = config.get('github_branch', 'main')
                url = f"https://api.github.com/repos/{repo}/contents/{path}"
                headers = {
                    "Authorization": f"Bearer {config['github_token']}",
                    "Accept": "application/vnd.github+json"
                }
                get_res = requests.get(url, headers=headers, params={"ref": branch})
                sha = get_res.json().get('sha') if get_res.status_code == 200 else None

                import base64
                encoded_bytes = base64.b64encode(file_json_str.encode('utf-8')).decode('utf-8')
                payload = {
                    "message": f"Auto-refresh tokens [{server}] via Telegram Bot Timer",
                    "content": encoded_bytes,
                    "branch": branch
                }
                if sha:
                    payload["sha"] = sha

                put_res = requests.put(url, headers=headers, json=payload)
                if put_res.status_code in (200, 201):
                    updated_servers.append(server)
                    add_log(f"GitHub file updated successfully for server: {server}")
            except Exception as e:
                add_log(f"GitHub sync error for {server}: {e}")

    # Send confirmation message immediately after GitHub upload
    if updated_servers:
        notify_owner(f"ɢɪᴛʜᴜʙ ᴜᴘᴅᴀᴛᴇᴅ ꜰᴏʀ: {', '.join(updated_servers)}")
    else:
        notify_owner("ɢɪᴛʜᴜʙ ᴜᴘᴅᴀᴛᴇᴅ ꜰᴏʀ: ɴᴏɴᴇ (ɴᴏ ɴᴇᴡ ᴛᴏᴋᴇɴꜱ ᴏʀ ɴᴏᴛ ᴄᴏɴꜰɪɢᴜʀᴇᴅ)")

    # Send the two separate files to the admin privately
    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    send_owner_document(
        f"success_tokens_{timestamp_str}.json", 
        json.dumps(succeeded_entries, indent=2), 
        f"ᴛɪᴍᴇʀ ʀᴇꜱᴜʟᴛ: {len(succeeded_entries)} ꜱᴜᴄᴄᴇꜱꜱꜰᴜʟ ᴛᴏᴋᴇɴꜱ"
    )
    send_owner_document(
        f"failed_tokens_{timestamp_str}.json", 
        json.dumps(failed_entries, indent=2), 
        f"ᴛɪᴍᴇʀ ʀᴇꜱᴜʟᴛ: {len(failed_entries)} ꜰᴀɪʟᴇᴅ ᴛᴏᴋᴇɴꜱ"
    )

scheduler = BackgroundScheduler()
scheduler.start()

def reschedule_timer():
    config = get_config()
    interval = int(config.get('timer_interval_hours', 6))
    for job in scheduler.get_jobs():
        job.remove()
    scheduler.add_job(background_timer_job, 'interval', hours=interval)
    add_log(f"Timer rescheduled for every {interval} hours.")

reschedule_timer()

# --- Telegram Bot Engine ---
BOT_THREAD = None
BOT_STATUS = "stopped"
BOT_STOP_EVENT = threading.Event()
BOT_LOCK = threading.Lock()

def build_persistent_reply_keyboard(user_id: int):
    """
    Creates persistent ReplyKeyboardMarkup positioned right above the text input.
    Colores:
      - 'success' (green): 'UID + PASSWORD', 'ACCESS TOKEN', 'GET LIKE API'
      - 'primary' (blue): '⚙️ Admin'
    """
    config = get_config()
    owner_id = config.get('owner_telegram_id')

    btn_uidpass = make_reply_button(to_small_caps("uid + password"), style="success")
    btn_token = make_reply_button(to_small_caps("access token"), style="success")
    btn_like = make_reply_button(to_small_caps("get like api"), style="success")

    keyboard_rows = [
        [btn_uidpass, btn_token],
        [btn_like]
    ]

    # Admin button for owner only
    if owner_id and int(user_id) == int(owner_id):
        btn_admin = make_reply_button(to_small_caps("⚙️ admin"), style="primary")
        keyboard_rows[1].append(btn_admin)

    return ReplyKeyboardMarkup(keyboard_rows, resize_keyboard=True)

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    config = get_config()
    
    # Configure Mini App Menu Button (bottom-left) pointing to specified URL
    miniapp_url = config.get("miniapp_url", "https://jwt-web-telligram.onrender.com/")
    try:
        await context.bot.set_chat_menu_button(
            chat_id=user.id,
            menu_button=MenuButtonWebApp(
                text=to_small_caps("mini app"),
                web_app=WebAppInfo(url=miniapp_url)
            )
        )
    except Exception as e:
        add_log(f"set_chat_menu_button error: {e}")

    reply_markup = build_persistent_reply_keyboard(user.id)
    welcome_msg = to_small_caps(
        f"hello {user.first_name}!\nwelcome to free fire token & like manager.\nchoose an action below or tap the mini app menu button."
    )
    await update.message.reply_text(welcome_msg, reply_markup=reply_markup)

# In-bot Admin Control Menu
async def show_admin_control_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    config = get_config()
    owner_id = config.get('owner_telegram_id')
    user_id = update.effective_user.id
    if not owner_id or int(user_id) != int(owner_id):
        await update.message.reply_text(to_small_caps("access denied. admin only."))
        return

    admin_keyboard = [
        [
            make_inline_button(to_small_caps("📊 view stats"), callback_data="admin_view_stats", style="primary"),
            make_inline_button(to_small_caps("⚡ run timer now"), callback_data="admin_run_timer", style="success")
        ],
        [
            make_inline_button(to_small_caps("🌐 servers list"), callback_data="admin_servers", style="primary"),
            make_inline_button(to_small_caps("👥 account counts"), callback_data="admin_accounts", style="primary")
        ],
        [
            make_inline_button(to_small_caps("❌ close menu"), callback_data="admin_close", style="danger")
        ]
    ]
    menu_text = to_small_caps("⚙️ admin control panel\nchoose an administrative action:")
    await update.message.reply_text(menu_text, reply_markup=InlineKeyboardMarkup(admin_keyboard))

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    config = get_config()
    user_id = query.from_user.id
    owner_id = config.get('owner_telegram_id')

    if data.startswith("srv_up_"):
        server = data.split("_")[2]
        context.user_data['pending_flow'] = 'uid_pass'
        context.user_data['server'] = server
        prompt = to_small_caps(
            f"server {server} selected.\nnow send single uid:password or upload/paste bulk json list:"
        )
        await query.edit_message_text(prompt)

    elif data.startswith("srv_at_"):
        server = data.split("_")[2]
        context.user_data['pending_flow'] = 'access_token'
        context.user_data['server'] = server
        prompt = to_small_caps(
            f"server {server} selected.\nnow send access token or upload/paste bulk json list:"
        )
        await query.edit_message_text(prompt)

    elif data == "admin_view_stats":
        if not owner_id or int(user_id) != int(owner_id):
            return
        entries = get_all_entries()
        uid_cnt = sum(1 for e in entries if e.get('type') == 'uid_pass')
        token_cnt = sum(1 for e in entries if e.get('type') == 'access_token')
        stats_text = to_small_caps(
            f"📊 live statistics:\n- total accounts: {len(entries)}\n- uid+pass: {uid_cnt}\n- access tokens: {token_cnt}\n- bot status: {BOT_STATUS}\n- timer: every {config.get('timer_interval_hours', 6)}h"
        )
        await query.edit_message_text(stats_text)

    elif data == "admin_run_timer":
        if not owner_id or int(user_id) != int(owner_id):
            return
        threading.Thread(target=background_timer_job, daemon=True).start()
        await query.edit_message_text(to_small_caps("⚡ background timer run started now! reports will be sent upon completion."))

    elif data == "admin_servers":
        servers = config.get("servers", [])
        entries = get_all_entries()
        lines = [f"- {s}: {sum(1 for e in entries if e.get('server') == s)} accounts" for s in servers]
        txt = to_small_caps("🌐 configured servers:\n" + "\n".join(lines))
        await query.edit_message_text(txt)

    elif data == "admin_accounts":
        entries = get_all_entries()
        txt = to_small_caps(f"👥 database holds {len(entries)} accounts across all servers.")
        await query.edit_message_text(txt)

    elif data == "admin_close":
        await query.delete_message()

async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (update.message.text or "").strip()
    user_id = update.effective_user.id
    config = get_config()
    owner_id = config.get('owner_telegram_id')

    # 1. Match Persistent Reply Keyboard Buttons
    uid_pass_btn_text = to_small_caps("uid + password")
    access_token_btn_text = to_small_caps("access token")
    get_like_btn_text = to_small_caps("get like api")
    admin_btn_text = to_small_caps("⚙️ admin")

    if text in (uid_pass_btn_text, "UID + PASSWORD", "uid + password"):
        servers = config.get("servers", ["IND", "BD"])
        # Server buttons styled primary blue
        keyboard = [[make_inline_button(to_small_caps(s), callback_data=f"srv_up_{s}", style="primary")] for s in servers]
        await update.message.reply_text(
            to_small_caps("select game server for uid + password:"),
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    elif text in (access_token_btn_text, "ACCESS TOKEN", "access token"):
        servers = config.get("servers", ["IND", "BD"])
        keyboard = [[make_inline_button(to_small_caps(s), callback_data=f"srv_at_{s}", style="primary")] for s in servers]
        await update.message.reply_text(
            to_small_caps("select game server for access token:"),
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return

    elif text in (get_like_btn_text, "GET LIKE API", "get like api"):
        all_entries = get_all_entries()
        user_entries = [e for e in all_entries if e.get('telegram_id') == user_id]
        
        unlocked = False
        for e in user_entries:
            # TODO: Map account level from decoded JWT payload or database entry (e.g., e.get('level')).
            # Developer should confirm exact account level field name in JWT response payload.
            level = e.get('level', 8)
            if level >= 8:
                unlocked = True
                break

        if unlocked:
            like_url = to_small_caps(config.get('like_api_url', 'https://example.com/like-api'))
            msg = to_small_caps(f"access granted!\nyour like api endpoint:\n{like_url}")
            await update.message.reply_text(msg)
        else:
            msg = to_small_caps("upload an access token or uid+password (account level 8+) to unlock.")
            await update.message.reply_text(msg)
        return

    elif text in (admin_btn_text, "⚙️ ADMIN", "admin"):
        if owner_id and int(user_id) == int(owner_id):
            await show_admin_control_menu(update, context)
        return

    # 2. Check pending flow for data submission
    flow = context.user_data.get('pending_flow')
    server = context.user_data.get('server', 'IND')

    if not flow:
        await update.message.reply_text(
            to_small_caps("please tap one of the buttons below to choose an action."),
            reply_markup=build_persistent_reply_keyboard(user_id)
        )
        return

    raw_items = []
    is_bulk = False

    # Check if text is JSON (single object or list)
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            raw_items = parsed
            if len(raw_items) > 1:
                is_bulk = True
        elif isinstance(parsed, dict):
            raw_items = [parsed]
    except Exception:
        # Single typed manual input
        if flow == 'uid_pass':
            parts = text.split(':')
            if len(parts) >= 2:
                raw_items = [{"uid": parts[0].strip(), "password": parts[1].strip()}]
        elif flow == 'access_token':
            raw_items = [{"access_token": text.strip()}]

    if not raw_items:
        await update.message.reply_text(to_small_caps("invalid format. please check and try again."))
        return

    res = process_submission(user_id, server, flow, raw_items, is_bulk=is_bulk)
    context.user_data['pending_flow'] = None

    if is_bulk:
        summary = to_small_caps(
            f"bulk submission saved:\n- added: {res['added']}\n- duplicate: {res['duplicate']}\n- invalid: {res['invalid']}\n(jwt tokens will regenerate on scheduled timer run.)"
        )
    else:
        summary = to_small_caps(
            f"submission results:\n- added: {res['added']}\n- duplicate: {res['duplicate']}\n- invalid: {res['invalid']}"
        )
    await update.message.reply_text(summary, reply_markup=build_persistent_reply_keyboard(user_id))

    # Forward raw submitted data to admin privately
    notify_owner(f"submission from user {user_id} (server {server}, type {flow}):\n{text}")

# Handle file uploads (JSON bulk upload)
async def handle_document_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    user_id = update.effective_user.id
    flow = context.user_data.get('pending_flow')
    server = context.user_data.get('server', 'IND')

    if not flow:
        await update.message.reply_text(to_small_caps("please select a button first (uid+password or access token)."))
        return

    try:
        tg_file = await doc.get_file()
        file_bytes = await tg_file.download_as_bytearray()
        content = file_bytes.decode('utf-8')
        data = json.loads(content)
        items = data if isinstance(data, list) else [data]
        is_bulk = len(items) > 1
        res = process_submission(user_id, server, flow, items, is_bulk=is_bulk)
        context.user_data['pending_flow'] = None

        reply_msg = to_small_caps(
            f"file processed:\n- added: {res['added']}\n- duplicate: {res['duplicate']}\n- invalid: {res['invalid']}"
        )
        await update.message.reply_text(reply_msg, reply_markup=build_persistent_reply_keyboard(user_id))
        notify_owner(f"file uploaded by {user_id} ({doc.file_name}): {len(items)} entries")
    except Exception as e:
        await update.message.reply_text(to_small_caps(f"error processing file: {str(e)}"))

def bot_thread_worker(token: str):
    global BOT_STATUS
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    async def runner():
        global BOT_STATUS
        try:
            application = ApplicationBuilder().token(token).build()
            application.add_handler(CommandHandler("start", start_command))
            application.add_handler(CallbackQueryHandler(button_callback))
            application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message))
            application.add_handler(MessageHandler(filters.Document.ALL, handle_document_message))
            
            await application.initialize()
            await application.start()
            await application.updater.start_polling(drop_pending_updates=True)
            BOT_STATUS = "running"
            add_log(f"Telegram Bot started successfully with token {mask_token(token)}")
            
            while not BOT_STOP_EVENT.is_set():
                await asyncio.sleep(1)
                
            add_log("Telegram Bot shutting down...")
            await application.updater.stop()
            await application.stop()
            await application.shutdown()
            BOT_STATUS = "stopped"
            add_log("Telegram Bot stopped.")
        except Exception as e:
            add_log(f"Telegram Bot error: {e}")
            BOT_STATUS = f"error: {str(e)}"

    try:
        loop.run_until_complete(runner())
    finally:
        loop.close()

def stop_bot_if_running():
    global BOT_THREAD, BOT_STATUS
    if BOT_THREAD and BOT_THREAD.is_alive():
        add_log("Signaling stop to bot thread...")
        BOT_STOP_EVENT.set()
        BOT_THREAD.join(timeout=4)
        BOT_STATUS = "stopped"

def start_or_restart_bot():
    global BOT_THREAD, BOT_STATUS
    with BOT_LOCK:
        config = get_config()
        token = (config.get('bot_token') or "").strip()
        
        stop_bot_if_running()
        BOT_STOP_EVENT.clear()
        
        if not token:
            BOT_STATUS = "stopped"
            add_log("No bot token set. Bot remains offline.")
            return False, "Bot is uninitialized. Configure Bot Token in Admin Panel."
            
        add_log(f"Starting bot thread with token {mask_token(token)}...")
        BOT_THREAD = threading.Thread(target=bot_thread_worker, args=(token,), daemon=True)
        BOT_THREAD.start()
        return True, "Bot starting..."

# --- WebApp Verification & Admin Context Security ---
def verify_telegram_init_data(init_data: str, bot_token: str) -> dict:
    if not init_data or not bot_token:
        return None
    try:
        parsed = dict(parse_qsl(init_data))
        received_hash = parsed.pop('hash', None)
        if not received_hash:
            return None
        
        data_check_string = '\n'.join([f"{k}={v}" for k, v in sorted(parsed.items())])
        secret_key = hmac.new(b"WebAppData", bot_token.encode('utf-8'), hashlib.sha256).digest()
        calculated_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()
        
        if hmac.compare_digest(calculated_hash, received_hash):
            if 'user' in parsed:
                return json.loads(parsed['user'])
        return None
    except Exception as e:
        add_log(f"initData verification error: {e}")
        return None

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

@app.route('/ping')
def ping():
    return "OK", 200

# Setup API
@app.route('/api/setup', methods=['GET', 'POST'])
def api_setup():
    config = get_config()
    if request.method == 'GET':
        return jsonify({
            "is_configured": bool(config.get("bot_token")),
            "bot_token_masked": mask_token(config.get("bot_token", "")),
            "owner_telegram_id": config.get("owner_telegram_id") or "",
            "bot_status": BOT_STATUS
        })
    else:
        data = request.json or {}
        new_token = (data.get("bot_token") or "").strip()
        owner_id = data.get("owner_telegram_id")
        admin_pw = data.get("admin_password")
        
        if new_token and not new_token.startswith("••"):
            config["bot_token"] = new_token
            
        if owner_id is not None and str(owner_id).strip() != "":
            try:
                config["owner_telegram_id"] = int(owner_id)
            except ValueError:
                return jsonify({"error": "Admin Telegram ID must be a numeric value"}), 400
                
        if admin_pw:
            config["admin_password_hash"] = generate_password_hash(admin_pw)
            
        update_config(config)
        started, msg = start_or_restart_bot()
        return jsonify({
            "status": "success",
            "message": msg,
            "bot_status": BOT_STATUS,
            "bot_token_masked": mask_token(config.get("bot_token", ""))
        })

@app.route('/api/bot_action', methods=['POST'])
def api_bot_action():
    data = request.json or {}
    action = data.get('action')
    if action == 'restart':
        started, msg = start_or_restart_bot()
        return jsonify({"status": "success", "message": msg, "bot_status": BOT_STATUS})
    elif action == 'stop':
        stop_bot_if_running()
        return jsonify({"status": "success", "message": "Bot stopped", "bot_status": BOT_STATUS})
    elif action == 'trigger_timer':
        threading.Thread(target=background_timer_job, daemon=True).start()
        return jsonify({"status": "success", "message": "Timer refresh triggered in background."})
    return jsonify({"error": "Unknown action"}), 400

@app.route('/api/admin_check_auth', methods=['POST'])
def admin_check_auth():
    data = request.json or {}
    init_data = data.get('initData', '')
    config = get_config()
    
    if init_data and config.get('bot_token'):
        user_info = verify_telegram_init_data(init_data, config['bot_token'])
        if user_info:
            user_id = user_info.get('id')
            owner_id = config.get('owner_telegram_id')
            if owner_id and user_id == owner_id:
                return jsonify({"authorized": True, "is_owner": True, "user_id": user_id})
            else:
                return jsonify({
                    "authorized": False, 
                    "is_owner": False, 
                    "error": f"Unauthorized. Admin panel is restricted to Owner ID: {owner_id}."
                })
    return jsonify({"authorized": False, "is_owner": False})

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if request.method == 'GET':
        config = get_config().copy()
        config['bot_token'] = mask_token(config.get('bot_token', ''))
        config.pop('admin_password_hash', None)
        return jsonify(config)
    else:
        data = request.json or {}
        config = get_config()
        token_changed = False
        
        for k, v in data.items():
            if k == 'admin_password' and v:
                config['admin_password_hash'] = generate_password_hash(v)
            elif k == 'bot_token':
                if v and not str(v).startswith("••"):
                    config['bot_token'] = v
                    token_changed = True
            elif k == 'owner_telegram_id' and v:
                try:
                    config['owner_telegram_id'] = int(v)
                except ValueError:
                    pass
            else:
                config[k] = v
                
        update_config(config)
        reschedule_timer()
        
        if token_changed:
            start_or_restart_bot()
            
        return jsonify({"status": "success", "bot_status": BOT_STATUS})

@app.route('/api/stats', methods=['GET'])
def api_stats():
    config = get_config()
    entries = get_all_entries()
    uid_pass_count = sum(1 for e in entries if e.get('type') == 'uid_pass')
    access_token_count = sum(1 for e in entries if e.get('type') == 'access_token')
    
    server_counts = {}
    for s in config.get('servers', []):
        server_counts[s] = sum(1 for e in entries if e.get('server') == s)

    return jsonify({
        "total_entries": len(entries),
        "uid_pass_count": uid_pass_count,
        "access_token_count": access_token_count,
        "server_counts": server_counts,
        "servers": config.get('servers', []),
        "bot_status": BOT_STATUS,
        "bot_configured": bool(config.get("bot_token")),
        "recent_logs": RECENT_LOGS[-30:]
    })

# --- Full Backup & Restore (Settings + Accounts) ---
@app.route('/api/backup', methods=['GET'])
def api_backup():
    config = get_config()
    entries = get_all_entries()
    backup_data = {
        "config": config,
        "entries": entries,
        "backup_time": datetime.utcnow().isoformat()
    }
    file_path = "full_system_backup.json"
    with open(file_path, "w") as f:
        json.dump(backup_data, f, indent=2)
    return send_file(file_path, as_attachment=True)

@app.route('/api/restore', methods=['POST'])
def api_restore():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    try:
        data = json.load(file)
        if "config" in data:
            update_config(data["config"])
        if "entries" in data:
            if USE_MONGO:
                DB.entries.delete_many({})
                if data["entries"]:
                    DB.entries.insert_many(data["entries"])
            else:
                ldb = load_local_db()
                ldb["entries"] = data["entries"]
                save_local_db(ldb)
        reschedule_timer()
        start_or_restart_bot()
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# --- Accounts-Only Backup & Restore (No Settings/Tokens) ---
@app.route('/api/backup_accounts', methods=['GET'])
def api_backup_accounts():
    entries = get_all_entries()
    # Filter to only account fields
    accounts_only = []
    for e in entries:
        accounts_only.append({
            "uid": e.get("uid"),
            "password": e.get("password"),
            "access_token": e.get("access_token"),
            "server": e.get("server"),
            "account_id": e.get("account_id"),
            "token": e.get("token"),
            "type": e.get("type"),
            "timestamp": e.get("timestamp")
        })
    filename = f"accounts_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    file_path = "accounts_export.json"
    with open(file_path, "w") as f:
        json.dump(accounts_only, f, indent=2)
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route('/api/restore_accounts', methods=['POST'])
def api_restore_accounts():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    try:
        entries = json.load(file)
        if not isinstance(entries, list):
            return jsonify({"error": "Expected a JSON array of account objects."}), 400
        
        added = 0
        dup = 0
        invalid = 0
        all_existing = get_all_entries()

        for item in entries:
            acc_type = item.get("type")
            server = item.get("server", "IND")
            account_id = item.get("account_id")
            uid = item.get("uid")
            acc_token = item.get("access_token")

            if acc_type == "uid_pass":
                if not uid or not item.get("password"):
                    invalid += 1
                    continue
                # Same UID dedupe rule
                if any(e for e in all_existing if e.get("type") == "uid_pass" and e.get("uid") == uid):
                    dup += 1
                    continue
            elif acc_type == "access_token":
                if not acc_token:
                    invalid += 1
                    continue
                # Same access_token dedupe rule
                if any(e for e in all_existing if e.get("type") == "access_token" and e.get("access_token") == acc_token):
                    dup += 1
                    continue
            else:
                invalid += 1
                continue

            # Account ID dedupe
            if account_id:
                existing = next((e for e in all_existing if e.get("account_id") == account_id), None)
                if existing:
                    if acc_type == "uid_pass" and existing.get("type") == "access_token":
                        delete_entry_db(account_id)
                        all_existing = [e for e in all_existing if e.get("account_id") != account_id]
                    elif existing.get("type") == acc_type:
                        dup += 1
                        continue

            save_entry_db(item)
            all_existing.append(item)
            added += 1

        add_log(f"Accounts restored: {added} added, {dup} duplicate, {invalid} invalid")
        return jsonify({"status": "success", "added": added, "duplicate": dup, "invalid": invalid})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/admin_login', methods=['POST'])
def admin_login():
    data = request.json or {}
    password = data.get('password')
    config = get_config()
    if check_password_hash(config.get('admin_password_hash', ''), password):
        return jsonify({"status": "success"})
    return jsonify({"error": "Invalid password"}), 401

@app.route('/api/submit_uidpass', methods=['POST'])
def api_submit_uidpass():
    data = request.json or {}
    init_data = data.get('initData', '')
    config = get_config()
    
    telegram_id = 12345
    if init_data and config.get('bot_token'):
        user_info = verify_telegram_init_data(init_data, config['bot_token'])
        if user_info:
            telegram_id = user_info.get('id', 12345)

    server = data.get('server', 'IND')
    items = data.get('items', [])
    if not items and data.get('uid'):
        items = [{"uid": data.get('uid'), "password": data.get('password')}]

    is_bulk = len(items) > 1
    res = process_submission(telegram_id, server, 'uid_pass', items, is_bulk=is_bulk)
    return jsonify(res)

@app.route('/api/submit_token', methods=['POST'])
def api_submit_token():
    data = request.json or {}
    init_data = data.get('initData', '')
    config = get_config()
    
    telegram_id = 12345
    if init_data and config.get('bot_token'):
        user_info = verify_telegram_init_data(init_data, config['bot_token'])
        if user_info:
            telegram_id = user_info.get('id', 12345)

    server = data.get('server', 'IND')
    items = data.get('items', [])
    if not items and data.get('access_token'):
        items = [{"access_token": data.get('access_token')}]

    is_bulk = len(items) > 1
    res = process_submission(telegram_id, server, 'access_token', items, is_bulk=is_bulk)
    return jsonify(res)

@app.route('/api/get_like_api', methods=['POST'])
def api_get_like_api():
    data = request.json or {}
    init_data = data.get('initData', '')
    config = get_config()
    
    telegram_id = 12345
    if init_data and config.get('bot_token'):
        user_info = verify_telegram_init_data(init_data, config['bot_token'])
        if user_info:
            telegram_id = user_info.get('id', 12345)

    entries = get_all_entries()
    user_entries = [e for e in entries if e.get('telegram_id') == telegram_id]
    
    unlocked = False
    for e in user_entries:
        level = e.get('level', 8)
        if level >= 8:
            unlocked = True
            break

    if unlocked:
        return jsonify({"unlocked": True, "like_api_url": config.get('like_api_url')})
    else:
        return jsonify({"unlocked": False, "message": "upload an access token or uid+password (account level 8+) to unlock."})

if __name__ == '__main__':
    init_cfg = get_config()
    if init_cfg.get('bot_token'):
        add_log("Stored bot token detected. Initializing bot...")
        start_or_restart_bot()
    else:
        add_log("No bot token set. Running Web Server for /admin setup.")

    app.run(host='0.0.0.0', port=3000, debug=False)
