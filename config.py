from dotenv import load_dotenv
import os

# Load environment variables from the .env file, if present
load_dotenv()

# Telegram API credentials obtained from https://my.telegram.org/auth
API_ID=10247139
API_HASH="96b46175824223a33737657ab943fd6a"

# List of Telegram bot tokens used for file upload/download operations
#BOT_TOKENS = os.getenv("BOT_TOKENS", "6769415354:AAHh7IfKn11PWuNxUo0qmoIuW7NclxaaFHQ").strip(", ").split(",")
BOT_TOKENS = os.getenv("BOT_TOKENS", "7341876935:AAGA0OsJjpGgWHnGK_MKMWoWpKRfkDgushI").strip(", ").split(",")
BOT_TOKENS = [token.strip() for token in BOT_TOKENS if token.strip() != ""]

# List of Premium Telegram Account Pyrogram String Sessions used for file upload/download operations
STRING_SESSIONS = os.getenv("STRING_SESSIONS", "").strip(", ").split(",")
STRING_SESSIONS = [
    session.strip() for session in STRING_SESSIONS if session.strip() != ""
]

# Chat ID of the Telegram storage channel where files will be stored
STORAGE_CHANNEL = -1002228842729

# Message ID of a file in the storage channel used for storing database backups
DATABASE_BACKUP_MSG_ID = 1296 #Message ID for database backup

# Password used to access the website's admin panel
ADMIN_PASSWORD = ["1863307059", "590009569", "162010513", "1498366357", "5419097944"]  # Default to "admin" if not set

# Determine the maximum file size (in bytes) allowed for uploading to Telegram
# 1.98 GB if no premium sessions are provided, otherwise 3.98 GB
if len(STRING_SESSIONS) == 0:
    MAX_FILE_SIZE = 1.98 * 1024 * 1024 * 1024  # 2 GB in bytes
else:
    MAX_FILE_SIZE = 3.98 * 1024 * 1024 * 1024  # 4 GB in bytes

# Database backup interval in seconds. Backups will be sent to the storage channel at this interval
DATABASE_BACKUP_TIME = int(
    os.getenv("DATABASE_BACKUP_TIME", 60)
)  # Default to 60 seconds

# Time delay in seconds before retrying after a Telegram API floodwait error
SLEEP_THRESHOLD = int(os.getenv("SLEEP_THRESHOLD", 60))  # Default to 60 seconds

# Domain to auto-ping and keep the website active
WEBSITE_URL = os.getenv("WEBSITE_URL", None)


# For Using TG Drive's Bot Mode

# Main Bot Token for TG Drive's Bot Mode
#MAIN_BOT_TOKEN = os.getenv("MAIN_BOT_TOKEN", "6769415354:AAHh7IfKn11PWuNxUo0qmoIuW7NclxaaFHQ")
MAIN_BOT_TOKEN = os.getenv("MAIN_BOT_TOKEN", "7341876935:AAGA0OsJjpGgWHnGK_MKMWoWpKRfkDgushI")
if MAIN_BOT_TOKEN.strip() == "":
    MAIN_BOT_TOKEN = None

# List of Telegram User IDs who have admin access to the bot mode
TELEGRAM_ADMIN_IDS = os.getenv("TELEGRAM_ADMIN_IDS", "6542409825").strip(", ").split(",")
TELEGRAM_ADMIN_IDS = [int(id) for id in TELEGRAM_ADMIN_IDS if id.strip() != ""]
