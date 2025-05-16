from flask import Flask, request, jsonify, abort
import hashlib
import hmac
import time
import requests

app = Flask(__name__)

BOT_TOKEN = "7910612320:AAGEhI9VX0gw3BhwhgU2DJjqjYO6ShFDmHE"
BOT_USERNAME = "Lamin_confirmbot"
SECRET_KEY = hashlib.sha256(BOT_TOKEN.encode()).digest()

def verify_telegram_auth(data: dict) -> bool:
    auth_data = data.copy()
    hash_to_check = auth_data.pop('hash')
    data_check_arr = [f"{k}={auth_data[k]}" for k in sorted(auth_data)]
    data_check_string = '\n'.join(data_check_arr)
    hmac_hash = hmac.new(SECRET_KEY, data_check_string.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(hmac_hash, hash_to_check)

@app.route("/auth/telegram", methods=["POST"])
def telegram_auth():
    data = request.form.to_dict()
    if not verify_telegram_auth(data):
        abort(403, description="Invalid Telegram login data.")
    if time.time() - int(data.get("auth_date", 0)) > 86400:
        abort(403, description="Login expired.")
    send_telegram_message(chat_id=data["id"], text=f"Hello {data.get('first_name')}, you logged in!")
    return jsonify({"status": "ok", "user": data})

def send_telegram_message(chat_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    return requests.post(url, data={"chat_id": chat_id, "text": text})

if __name__ == "__main__":
    app.run()
