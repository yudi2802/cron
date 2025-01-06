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

# Load allowed user IDs from the file
def load_allowed_user_ids():
    if os.path.exists(ALLOWED_USER_IDS_FILE):
        with open(ALLOWED_USER_IDS_FILE, 'r') as file:
            return json.load(file)
    return []

# Save allowed user IDs to the file
def save_allowed_user_ids(user_ids):
    with open(ALLOWED_USER_IDS_FILE, 'w') as file:
        json.dump(user_ids, file)

# Load admin user IDs from the file
def load_admin_user_ids():
    if os.path.exists(ADMIN_USER_IDS_FILE):
        with open(ADMIN_USER_IDS_FILE, 'r') as file:
            return json.load(file)
    return []

# Save admin user IDs to the file
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

# EmailGenerator class to generate random emails
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
        self.allowed_user_ids = load_allowed_user_ids()  # Load the list of allowed user IDs
        self.admin_user_ids = load_admin_user_ids()  # Load the list of admin user IDs
        self.partner = os.getenv("PARTNER_ID")  # Read the partner ID from .env file
        self._setup_handlers()

    def _setup_handlers(self):
        self.application.add_handler(CommandHandler("viu", self.viu_command))
        self.application.add_handler(CommandHandler("add", self.add_command))
        self.application.add_handler(CommandHandler("start", self.start_command))
        self.application.add_handler(CommandHandler("admin", self.admin_command))
        self.application.add_handler(CommandHandler("delete", self.delete_command))
        self.application.add_handler(CommandHandler("mitra", self.mitra_command))  # Add /mitra command handler

    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.message.from_user.id

        if user_id in self.admin_user_ids:
            status = "Admin"
        elif user_id in self.allowed_user_ids:
            status = "Member"
        else:
            status = "Tidak berlangganan"

        await update.message.reply_text(
            f"📌ID Telegram Anda: {user_id}\n🤡 Status: {status}"
        )

    async def delete_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        try:
            if update.message.from_user.id not in self.admin_user_ids:
                await update.message.reply_text("Maaf, Anda bukan admin 🙏")
                return

            if len(context.args) != 2:
                await update.message.reply_text("🤡 Gunakan: /delete <admin atau allowed> <ID Telegram>")
                return

            list_type = context.args[0].lower()
            user_id_to_remove = context.args[1]

            try:
                user_id_to_remove = int(user_id_to_remove)
            except ValueError:
                await update.message.reply_text("‼️ID pengguna yang diberikan tidak valid.")
                return

            if list_type == "admin":
                if user_id_to_remove not in self.admin_user_ids:
                    await update.message.reply_text(f"⁉️User {user_id_to_remove} bukan admin.")
                    return

                self.admin_user_ids.remove(user_id_to_remove)
                save_admin_user_ids(self.admin_user_ids)
                await update.message.reply_text(f"👌User {user_id_to_remove} telah dihapus dari daftar admin.")

            elif list_type == "allowed":
                if user_id_to_remove not in self.allowed_user_ids:
                    await update.message.reply_text(f"⁉️User {user_id_to_remove} tidak ada dalam daftar allowed.")
                    return

                self.allowed_user_ids.remove(user_id_to_remove)
                save_allowed_user_ids(self.allowed_user_ids)
                await update.message.reply_text(f"👌User {user_id_to_remove} telah dihapus dari daftar allowed.")
            else:
                await update.message.reply_text("‼️Tipe tidak valid. Gunakan 'admin' atau 'allowed'.")

        except Exception as e:
            await update.message.reply_text(f"⁉️Terjadi kesalahan: {str(e)}")

    async def add_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        try:
            if update.message.from_user.id not in self.admin_user_ids:
                await update.message.reply_text("🙏 Maaf, Anda belum berlangganan.")
                return

            if len(context.args) != 1:
                await update.message.reply_text("🤡 Gunakan: /add <ID Telegram>")
                return

            new_user_id = context.args[0]

            try:
                new_user_id = int(new_user_id)
            except ValueError:
                await update.message.reply_text("😭ID pengguna yang diberikan tidak valid.")
                return

            if new_user_id in self.allowed_user_ids:
                await update.message.reply_text("😸ID pengguna ini sudah ada dalam daftar allowed.")
                return

            self.allowed_user_ids.append(new_user_id)
            save_allowed_user_ids(self.allowed_user_ids)
            await update.message.reply_text(f"🤩User {new_user_id} telah ditambahkan ke daftar allowed.")
        except Exception as e:
            await update.message.reply_text(f"⁉️Terjadi kesalahan: {str(e)}")

    async def admin_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        try:
            if update.message.from_user.id not in self.admin_user_ids:
                await update.message.reply_text("⚠️ Anda bukan admin!")
                return

            if len(context.args) != 1:
                await update.message.reply_text("🤡 Gunakan: /admin <ID Telegram>")
                return

            new_admin_id = context.args[0]

            try:
                new_admin_id = int(new_admin_id)
            except ValueError:
                await update.message.reply_text("😭ID pengguna yang diberikan tidak valid.")
                return

            if new_admin_id in self.admin_user_ids:
                await update.message.reply_text("😊ID pengguna ini sudah menjadi admin.")
                return

            self.admin_user_ids.append(new_admin_id)
            save_admin_user_ids(self.admin_user_ids)
            await update.message.reply_text(f"😁User {new_admin_id} telah ditambahkan sebagai admin.")
        except Exception as e:
            await update.message.reply_text(f"⁉️Terjadi kesalahan: {str(e)}")

    async def check_permission(self, update: Update):
        if update.message.from_user.id not in self.admin_user_ids:
            await update.message.reply_text("🚫 Akses ditolak! Hubungi penyedia untuk info lebih lanjut.")
            return False
        return True

    async def viu_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not await self.check_permission(update):
            return

        try:
            message = update.message.text.split()
            if len(message) != 4:
                await update.message.reply_text("🤡 Gunakan: /viu <@domain> <password> <jumlah>")
                return

            domain, password, jumlah_akun = message[1], message[2], int(message[3])

            if jumlah_akun <= 0:
                await update.message.reply_text("😢Jumlah akun harus lebih dari 0.")
                return

            # Tambahkan batas maksimum jumlah akun
            if jumlah_akun > 50:
                await update.message.reply_text("📌 Max input untuk sekali run adalah 50 akun.")
                return

            # Send "Processing..." message right after receiving the command
            processing_message = await update.message.reply_text("Sedang diproses⌚")

            # Generate accounts and save to a file asynchronously
            file_path = await self.create_accounts(domain, password, self.partner, jumlah_akun)

            # Send the file to the user
            with open(file_path, "rb") as file:
                await update.message.reply_document(document=file, filename=file_path)

            # Send success message after the file has been sent
            await update.message.reply_text("⭐ Berhasil membuat akun Viu Premium!")

            # Clean up the temporary file after sending
            os.remove(file_path)

            # Delete the "Processing..." message after completing the task
            await processing_message.delete()

        except Exception as e:
            await update.message.reply_text(f"‼️Terjadi kesalahan: {str(e)}")

    async def mitra_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.message.from_user.id

        if user_id not in self.allowed_user_ids and user_id not in self.admin_user_ids:
            await update.message.reply_text("⚠️ Anda tidak memiliki akses untuk menggunakan perintah ini.")
            return

        try:
            message = update.message.text.split()
            if len(message) != 5:
                await update.message.reply_text("🤡 Gunakan: /mitra <@domain> <password> <partner> <jumlah>")
                return

            domain, password, partner, jumlah_akun = message[1], message[2], message[3], int(message[4])

            if jumlah_akun <= 0:
                await update.message.reply_text("😢 Jumlah akun harus lebih dari 0.")
                return

            if jumlah_akun > 50:
                await update.message.reply_text("📌 Max input untuk sekali run adalah 50 akun.")
                return

            # Send "Processing..." message
            processing_message = await update.message.reply_text("Sedang diproses⌚")

            # Generate accounts and save to a file asynchronously
            file_path = await self.create_accounts(domain, password, partner, jumlah_akun)

            # Send the file to the user
            with open(file_path, "rb") as file:
                await update.message.reply_document(document=file, filename=file_path)

            # Send success message after the file has been sent
            await update.message.reply_text("⭐ Berhasil membuat akun Viu Premium!")

            # Clean up the temporary file after sending
            os.remove(file_path)

            # Delete the "Processing..." message
            await processing_message.delete()

        except Exception as e:
            await update.message.reply_text(f"‼️ Terjadi kesalahan: {str(e)}")

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

        file_path = f"Viu_{jumlah_akun}Premium.txt"

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
