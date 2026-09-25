from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DRAGON_DATA_DIR", BASE_DIR / "data"))
DB_PATH = Path(os.getenv("DRAGON_DB_PATH", DATA_DIR / "dragon.db"))
SECRET_PATH = Path(os.getenv("DRAGON_SECRET_PATH", DATA_DIR / ".secret"))
COOKIE_NAME = "dragon_session"
SESSION_TTL_SECONDS = 60 * 60 * 12
APP_NAME = "Dragon VPS Manager NG"
VERSION = "0.1.0-alpha"
ALLOWED_SERVICES = {
    "ssh": "OpenSSH",
    "nginx": "Nginx",
    "stunnel4": "Stunnel",
    "fail2ban": "Fail2ban",
}
