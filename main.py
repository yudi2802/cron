import logging
import json
import os
import platform
import random
import hashlib
import requests
import uuid
from datetime import datetime
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from dotenv import load_dotenv
import aiohttp
import asyncio
from flask import Flask
from threading import Thread
from datetime import timedelta

# ID admin utama (gantikan dengan ID Telegram admin utama Anda)
MAIN_ADMIN_ID = 6754416676  # Ganti dengan ID Telegram Anda

app = Flask('')

@app.route('/')
def home():
    return "Bot is running!"

def run():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    t = Thread(target=run)
    t.start()

# Load environment variables from the .env file
load_dotenv()

# Store the allowed user IDs and admin IDs files
ALLOWED_USER_IDS_FILE = 'allowed_users.json'
ADMIN_USER_IDS_FILE = 'admin.json'

def load_allowed_user_ids():
    if os.path.exists(ALLOWED_USER_IDS_FILE):
        with open(ALLOWED_USER_IDS_FILE, 'r') as file:
            data = json.load(file)
            # Jika data lama berupa list ID saja, tambahkan nilai default untuk expiry
            if isinstance(data, list) and all(isinstance(item, int) for item in data):
                return [{"id": item, "expiry": "N/A"} for item in data]
            return data
    return []

def load_admin_user_ids():
    if os.path.exists(ADMIN_USER_IDS_FILE):
        with open(ADMIN_USER_IDS_FILE, 'r') as file:
            data = json.load(file)
            # Jika data lama berupa list ID saja, tambahkan nilai default untuk expiry
            if isinstance(data, list) and all(isinstance(item, int) for item in data):
                return [{"id": item, "expiry": "N/A"} for item in data]
            return data

def save_allowed_user_ids(user_ids):
    with open(ALLOWED_USER_IDS_FILE, 'w') as file:
        json.dump(user_ids, file)

def save_admin_user_ids(admin_ids):
    with open(ADMIN_USER_IDS_FILE, 'w') as file:
        json.dump(admin_ids, file)
# Utils class to handle utility functions

class Utils:
    @staticmethod
    def guidv4(data=None):
        if data is None:
            data = uuid.uuid4().bytes
        else:
            data = bytes.fromhex(data)
        data = bytearray(data)
        data[6] = (data[6] & 0x0f) | 0x40
        data[8] = (data[8] & 0x3f) | 0x80
        return str(uuid.UUID(bytes=bytes(data)))

    @staticmethod
    def curl(body, headers, url):
        response = requests.post(url, data=body, headers=headers)
        return response.text

    @staticmethod
    def curl2(headers, url):
        response = requests.get(url, headers=headers)
        return response.text

    @staticmethod
    def getRandomBytes(length=16):
        return uuid.uuid4().bytes.hex()[:length]

    @staticmethod
    def getRandomByte(length=32):
        return uuid.uuid4().bytes.hex()[:length]

# Viu class to interact with the Viu API (Updated for async)
class Viu:
    def __init__(self):
        self.session = aiohttp.ClientSession()

    async def getDev(self):
        url = "https://um.viuapi.io/user/device?id1=" + Utils.getRandomBytes()
        headers = {
            "x-client-auth": "b6fea2dd3d110b12fbd23d7ab8cd0ba3",
            "accept": "application/json",
            "x-client": "android",
            "content-type": "application/json",
            "x-session-id": Utils.getRandomByte(),
            "x-request-id": Utils.guidv4(),
            "x-enable-drm": "true",
            "user-agent": "okhttp/4.9.3"
        }
        async with self.session.get(url, headers=headers) as response:
            data = await response.json()
            return data["deviceId"]

    async def getToken(self):
        devId = await self.getDev()
        url = "https://um.viuapi.io/user/identity"
        body = '{"deviceId":"' + devId + '"}'
        headers = {
            "x-client-auth": "b6fea2dd3d110b12fbd23d7ab8cd0ba3",
            "accept": "application/json",
            "x-client": "android",
            "content-type": "application/json",
            "x-session-id": Utils.getRandomByte(),
            "x-request-id": Utils.guidv4(),
            "x-enable-drm": "true",
            "user-agent": "okhttp/4.9.3",
            "content-length": str(len(body))
        }
        async with self.session.post(url, data=body, headers=headers) as response:
            data = await response.json()
            return data["token"]

    async def getIdentity(self, partner):
        devId = await self.getDev()
        url = "https://um.viuapi.io/user/identity"
        body = '{"deviceId":"' + devId + '","partnerId":"' + partner + '","partnerName":"Telkomsel"}'
        headers = {
            "x-client-auth": "b6fea2dd3d110b12fbd23d7ab8cd0ba3",
            "accept": "application/json",
            "x-client": "android",
            "content-type": "application/json",
            "x-session-id": Utils.getRandomByte(),
            "x-request-id": Utils.guidv4(),
            "x-enable-drm": "true",
            "authorization": await self.getToken(),
            "user-agent": "okhttp/4.9.3",
            "content-length": str(len(body))
        }
        async with self.session.post(url, data=body, headers=headers) as response:
            data = await response.json()
            return data["token"]

    async def getAccount(self, email, password, token):
        url = "https://um.viuapi.io/user/account"
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        body = f'{{"password":"{hashed_password}","principal":"{email}","providerCode":"email"}}'
        headers = {
            "x-client-auth": "b6fea2dd3d110b12fbd23d7ab8cd0ba3",
            "accept": "application/json",
            "x-client": "android",
            "content-type": "application/json",
            "x-session-id": Utils.getRandomByte(),
            "x-request-id": Utils.guidv4(),
            "x-enable-drm": "true",
            "authorization": token,
            "user-agent": "okhttp/4.9.3",
            "content-length": str(len(body))
        }
        async with self.session.post(url, data=body, headers=headers) as response:
            return await response.text()

    async def getUserId(self, partner, accountId, token):
        devId = await self.getDev()
        url = "https://um.viuapi.io/user/identity"
        body = '{"accountId":"' + accountId + '","deviceId":"' + devId + '","partnerId":"' + partner + '","partnerName":"Telkomsel"}'
        headers = {
            "x-client-auth": "b6fea2dd3d110b12fbd23d7ab8cd0ba3",
            "accept": "application/json",
            "x-client": "android",
            "content-type": "application/json",
            "x-session-id": Utils.getRandomByte(),
            "x-request-id": Utils.guidv4(),
            "x-enable-drm": "true",
            "authorization": token,
            "user-agent": "okhttp/4.9.3",
            "content-length": str(len(body))
        }
        async with self.session.post(url, data=body, headers=headers) as response:
            return await response.text()

    async def checkInfo(self, id, partner, user, tokenId):
        url = (
            f"https://um.viuapi.io/viuapp-bff/v1/my?appid=viu_android&ver=2.0&appver=2.1.0&fmt=json&platform=app&productId=1&iid={id}"
            f"&carrierid=72&model=SM-S918B&devicetimezone=&devicecountry=&languageid=id&geo=10&regionid=all&ccode=ID&appsessid="
            f"&offerid=tmsel.30.VIU_MAX30D2&msisdn={partner}&vuserid={user}&partner=Telkomsel&userid={user}&contentFlavour=all"
            f"&networkType=4g&deviceId={id}&configVersion=1.0&languageId=id&partnerName=Telkomsel"
        )
        headers = {
            "x-client-auth": "b6fea2dd3d110b12fbd23d7ab8cd0ba3",
            "authorization": tokenId,
            "accept": "application/json",
            "x-client": "android",
            "content-type": "application/json",
            "x-session-id": Utils.getRandomByte(),
            "x-request-id": Utils.guidv4(),
            "x-enable-drm": "true",
            "user-agent": "okhttp/4.9.3"
        }
        async with self.session.get(url, headers=headers) as response:
            return await response.json()

    async def close(self):
        await self.session.close()

class EmailGenerator:
    def __init__(self):
        self.password = ""
        self.partnerId = ""

    def rand5Char(self):
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))

    def randNumber(self):
        return str(random.randint(0, 99)).zfill(2)

    def getEmail(self, domain):
        return f"{self.rand5Char()}{self.randNumber()}{domain}"

    def getPassword(self, password):
        return password

    def getPartnerId(self, partnerId):
        return partnerId

class TelegramBot:
    def __init__(self, token):
        self.application = Application.builder().token(token).build()
        self.allowed_user_ids = load_allowed_user_ids()  # Load daftar member
        self.admin_user_ids = load_admin_user_ids()  # Load daftar admin
        self.partner = os.getenv("PARTNER_ID")  # Partner ID dari file .env
        self._setup_handlers()

    def _setup_handlers(self):
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("viu", self.restricted_handler(self.viu_command, ["member", "admin"])))
        self.application.add_handler(CommandHandler("mitra", self.restricted_handler(self.mitra_command, ["member", "admin"])))
        self.application.add_handler(CommandHandler("add", self.restricted_handler(self.add_command, ["admin"])))
        self.application.add_handler(CommandHandler("admin", self.restricted_handler(self.admin_command, ["admin"])))
        self.application.add_handler(CommandHandler("delete", self.restricted_handler(self.delete_command, ["admin"])))
        self.application.add_handler(CommandHandler("check", self.restricted_handler(self.check_command, ["admin"])))

    async def check_permission(self, update: Update):
        """Periksa tipe akses pengguna: admin utama, admin, member, atau tidak memiliki izin."""
        user_id = update.message.from_user.id
        if user_id == MAIN_ADMIN_ID:
            return "main_admin"
        if any(admin["id"] == user_id for admin in self.admin_user_ids):
            return "admin"
        if any(user["id"] == user_id for user in self.allowed_user_ids):
            return "member"
        return "none"

    def restricted_handler(self, command_handler, allowed_roles):
        """
        Wrapper untuk membatasi akses ke perintah berdasarkan role (main_admin, admin, member).
        :param command_handler: Fungsi handler perintah.
        :param allowed_roles: Daftar role yang diizinkan untuk mengakses perintah.
        """
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            user_role = await self.check_permission(update)
            if user_role not in allowed_roles and user_role != "main_admin":
                await update.message.reply_text("⚠️ Anda tidak memiliki akses untuk menggunakan perintah ini.")
                return
            await command_handler(update, context)
        return wrapper

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk perintah /start."""
        user_id = update.message.from_user.id
        current_time = datetime.now().strftime("%Y-%m-%d | %H:%M:%S")

        if user_id == MAIN_ADMIN_ID:
            status = "Admin Utama"
            expiry_date = "Tidak terbatas"
        elif any(admin["id"] == user_id for admin in self.admin_user_ids):
            status = "Admin"
            expiry_date = next(admin["expiry"] for admin in self.admin_user_ids if admin["id"] == user_id)
        elif any(user["id"] == user_id for user in self.allowed_user_ids):
            status = "Member"
            expiry_date = next(user["expiry"] for user in self.allowed_user_ids if user["id"] == user_id)
        else:
            status = "Tidak berlangganan"
            expiry_date = "N/A"

        await update.message.reply_text(
            f"📌 ID Telegram Anda: {user_id}\n"
            f"🤡 Status: {status}\n"
            f"⏳ Masa aktif hingga: {expiry_date}\n"
            f"⏰ Waktu Saat ini: {current_time}"
        )
        
    async def viu_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk perintah /viu."""
        try:
            message = update.message.text.split()
            if len(message) != 4:
                await update.message.reply_text("🤡 Gunakan: /viu <@domain> <password> <jumlah>")
                return

            domain, password, jumlah_akun = message[1], message[2], int(message[3])

            if jumlah_akun <= 0:
                await update.message.reply_text("😢Jumlah akun harus lebih dari 0.")
                return

            if jumlah_akun > 50:
                await update.message.reply_text("📌 Max input untuk sekali run adalah 50 akun.")
                return

            processing_message = await update.message.reply_text("Sedang diproses⌚")

            file_path = await self.create_accounts(domain, password, self.partner, jumlah_akun)

            with open(file_path, "rb") as file:
                await update.message.reply_document(document=file, filename=file_path)

            await update.message.reply_text("⭐ Berhasil membuat akun Viu Premium!")
            os.remove(file_path)
            await processing_message.delete()

        except Exception as e:
            await update.message.reply_text(f"‼️Terjadi kesalahan: {str(e)}")

    async def mitra_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk perintah /mitra."""
        try:
            if len(context.args) != 4:
                await update.message.reply_text("🤡 Gunakan: /mitra <@domain> <password> <partner> <jumlah>")
                return

            domain, password, partner, jumlah_akun = context.args

            jumlah_akun = int(jumlah_akun)
            if jumlah_akun <= 0 or jumlah_akun > 50:
                await update.message.reply_text("Jumlah akun harus antara 1 dan 50.")
                return

            processing_message = await update.message.reply_text("⌚ Sedang diproses...")

            file_path = await self.create_accounts(domain, password, partner, jumlah_akun)

            with open(file_path, "rb") as file:
                await update.message.reply_document(document=file, filename=file_path)

            await update.message.reply_text("⭐ Berhasil membuat akun Viu Premium!")
            os.remove(file_path)
            await processing_message.delete()

        except Exception as e:
            await update.message.reply_text(f"‼️ Terjadi kesalahan: {str(e)}")

    async def add_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk perintah /add."""
        try:
            if len(context.args) != 2:
                await update.message.reply_text("🤡 Gunakan: /add <ID Telegram> <durasi>")
                return

            new_user_id, duration = int(context.args[0]), int(context.args[1])
            expiry_date = (datetime.now() + timedelta(days=duration)).strftime("%Y-%m-%d | %H:%M:%S")

            if any(user["id"] == new_user_id for user in self.allowed_user_ids):
                await update.message.reply_text("😸 ID pengguna ini sudah ada dalam daftar member.")
                return

            self.allowed_user_ids.append({"id": new_user_id, "expiry": expiry_date})
            save_allowed_user_ids(self.allowed_user_ids)
            await update.message.reply_text(f"🤩 User {new_user_id} telah ditambahkan ke daftar member hingga {expiry_date}.")

        except Exception as e:
            await update.message.reply_text(f"⁉️ Terjadi kesalahan: {str(e)}")

    async def admin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk perintah /admin."""
        try:
            if len(context.args) != 2:
                await update.message.reply_text("🤡 Gunakan: /admin <ID Telegram> <durasi>")
                return

            new_admin_id, duration = int(context.args[0]), int(context.args[1])
            expiry_date = (datetime.now() + timedelta(days=duration)).strftime("%Y-%m-%d | %H:%M:%S")

            if any(admin["id"] == new_admin_id for admin in self.admin_user_ids):
                await update.message.reply_text("😊 ID pengguna ini sudah menjadi admin.")
                return

            self.admin_user_ids.append({"id": new_admin_id, "expiry": expiry_date})
            save_admin_user_ids(self.admin_user_ids)
            await update.message.reply_text(f"😁 User {new_admin_id} telah ditambahkan sebagai admin hingga {expiry_date}.")

        except Exception as e:
            await update.message.reply_text(f"⁉️ Terjadi kesalahan: {str(e)}")

    async def delete_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk perintah /delete."""
        try:
            if len(context.args) != 2:
                await update.message.reply_text("🤡 Gunakan: /delete <admin atau member> <ID Telegram>")
                return

            list_type, user_id_to_remove = context.args[0].lower(), int(context.args[1])

            if list_type == "admin":
                if not any(admin["id"] == user_id_to_remove for admin in self.admin_user_ids):
                    await update.message.reply_text(f"😢 User {user_id_to_remove} bukan admin.")
                    return

                self.admin_user_ids = [admin for admin in self.admin_user_ids if admin["id"] != user_id_to_remove]
                save_admin_user_ids(self.admin_user_ids)
                await update.message.reply_text(f"👌 User {user_id_to_remove} telah dihapus dari daftar admin.")

            elif list_type == "member":
                if not any(user["id"] == user_id_to_remove for user in self.allowed_user_ids):
                    await update.message.reply_text(f"😢 User {user_id_to_remove} tidak ada dalam daftar member.")
                    return

                self.allowed_user_ids = [user for user in self.allowed_user_ids if user["id"] != user_id_to_remove]
                save_allowed_user_ids(self.allowed_user_ids)
                await update.message.reply_text(f"👌 User {user_id_to_remove} telah dihapus dari daftar member.")

            else:
                await update.message.reply_text("‼️ Gunakan 'admin' atau 'member' sebagai tipe.")

        except Exception as e:
            await update.message.reply_text(f"⁉️ Terjadi kesalahan: {str(e)}")

    async def check_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk perintah /check."""
        user_id = update.message.from_user.id
        if user_id != MAIN_ADMIN_ID:
            await update.message.reply_text("⚠️ Anda tidak memiliki akses untuk menggunakan perintah ini.")
            return

        admin_list = [f"{admin['id']} | {admin['expiry']}" for admin in self.admin_user_ids]
        member_list = [f"{member['id']} | {member['expiry']}" for member in self.allowed_user_ids]

        admin_text = "Admin\n" + "\n".join(admin_list) if admin_list else "Tidak ada admin."
        member_text = "Member\n" + "\n".join(member_list) if member_list else "Tidak ada member."

        await update.message.reply_text(f"{admin_text}\n\n{member_text}")

    async def create_accounts(self, domain, password, partner, jumlah_akun):
        viu = Viu()
        email_generator = EmailGenerator()

        # Override domain, password, and partner from the command
        email_generator.password = password
        email_generator.partnerId = partner

        accounts_info = ""  # To store all the generated accounts

        tasks = []
        for i in range(1, jumlah_akun + 1):
            tasks.append(self.create_single_account(email_generator, viu, domain, i))

        # Await all tasks to complete in parallel
        results = await asyncio.gather(*tasks)

        for result in results:
            accounts_info += result

        file_path = f"Account{jumlah_akun}Premium.txt"

        # Save the accounts info to the file
        with open(file_path, "w") as file:
            file.write(accounts_info)

        return file_path  # Return the path to the created file

    async def create_single_account(self, email_generator, viu, domain, account_num):
        email = email_generator.getEmail(domain)
        password = email_generator.getPassword(email_generator.password)
        partnerId = email_generator.getPartnerId(email_generator.partnerId)

        identity_token = await viu.getIdentity(partnerId)
        account_info = await viu.getAccount(email, password, identity_token)
        account_info_json = json.loads(account_info)

        if "accountId" not in account_info_json:
            logging.error(f"Missing accountId in response for email: {email}. Response: {account_info_json}")
            return ""

        accountId = account_info_json["accountId"]
        userId_response = await viu.getUserId(partnerId, accountId, identity_token)
        user_info_json = json.loads(userId_response)

        if "userId" not in user_info_json or "token" not in user_info_json:
            logging.error(f"Missing userId or token in response for accountId: {accountId}. Response: {user_info_json}")
            return ""

        userId = user_info_json["userId"]
        tokenId = user_info_json["token"]
        package_info = await viu.checkInfo(accountId, partnerId, userId, tokenId)

        if 'MyAccount' not in package_info or len(package_info['MyAccount']) == 0:
            logging.error(f"Missing package info for userId: {userId}. Response: {package_info}")
            return ""

        validity = package_info['MyAccount'][0]['userPLan']['Validity'].strip()
        now = datetime.now().strftime("%d-%m-%Y")
        return f"{email} - {password} | {validity} Days - {now}\n"

def clear_console():
    """Membersihkan konsol berdasarkan sistem operasi."""
    if platform.system() == "Windows":
        os.system("cls")  # Perintah untuk Windows
    else:
        os.system("clear")  # Perintah untuk Unix/Linux        

if __name__ == '__main__':
    load_dotenv()

    token = os.getenv("TELEGRAM_TOKEN")
    if not token:
        raise ValueError("Token tidak ditemukan di file .env!")

    clear_console()
    keep_alive()
    print("[info] Bot sedang berjalan...")
    
    bot = TelegramBot(token=token)
    bot.application.run_polling()
