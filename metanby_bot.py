import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Union
import csv
import aiofiles
import asyncpg
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command, StateFilter
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.utils.keyboard import InlineKeyboardBuilder, ReplyKeyboardBuilder
from aiogram.types import Message, CallbackQuery, ReplyKeyboardRemove, BufferedInputFile
from pydantic import BaseModel, EmailStr, ValidationError, field_validator
from dotenv import load_dotenv
import redis
import asyncio
import shutil
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn
import sentry_sdk
from sentry_sdk.integrations.asyncio import AsyncioIntegration
from sentry_sdk.integrations.logging import LoggingIntegration
import html
import re
from fastapi.responses import FileResponse, RedirectResponse
from pathlib import Path
import subprocess
from aiogram.types import BufferedInputFile
from fastapi import Form
from fastapi.responses import StreamingResponse
from io import StringIO
import json
import sentry_sdk
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware
from aiogram.fsm.storage.redis import RedisStorage
from aiogram.exceptions import TelegramBadRequest

# Создаем необходимые директории перед инициализацией приложения
os.makedirs("static", exist_ok=True)
os.makedirs("templates", exist_ok=True)
os.makedirs("backups", exist_ok=True)
os.makedirs("temp", exist_ok=True)

# Настройка расширенного логирования
class SecurityFilter(logging.Filter):
    def filter(self, record):
        if isinstance(record.msg, str):
            record.msg = re.sub(r'(\+375\d{9})', r'******', record.msg)
            record.msg = re.sub(r'(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b)', r'******', record.msg)
            record.msg = re.sub(r'(\b\d{9}\b)', r'******', record.msg)
            record.msg = re.sub(r'(\bIBAN BY\w+)', r'******', record.msg)
        return True

load_dotenv()

# Sentry initialization
sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    integrations=[
        AsyncioIntegration(),
        LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)
    ],
    traces_sample_rate=1.0,
    environment=os.getenv("ENVIRONMENT", "development")
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s [%(filename)s:%(lineno)d]",
    handlers=[
        RotatingFileHandler(
            "bot.log",
            maxBytes=5*1024*1024,
            backupCount=10,
            encoding='utf-8'
        ),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)
logger.addFilter(SecurityFilter())



# Configuration class
class Config:
    def __init__(self):
        self.BOT_TOKEN = os.getenv("BOT_TOKEN")
        self.ADMIN_ID = int(os.getenv("ADMIN_ID", 0))
        self.MODERATOR_IDS = [int(id) for id in os.getenv("MODERATOR_IDS", "").split(",") if id]
        self.POSTGRES_DSN = os.getenv("POSTGRES_DSN")
        self.REDIS_HOST = os.getenv("REDIS_HOST")
        self.REDIS_PORT = int(os.getenv("REDIS_PORT"))
        self.REDIS_DB = int(os.getenv("REDIS_DB"))
        self.ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
        self.SENTRY_DSN = os.getenv("SENTRY_DSN")
        self.ENVIRONMENT = os.getenv("ENVIRONMENT")

        
        if not self.BOT_TOKEN:
            raise ValueError("BOT_TOKEN is required")
        if not self.ADMIN_ID:
            raise ValueError("ADMIN_ID is required")

config = Config()

# Initialize bot and dispatcher
bot = Bot(token=config.BOT_TOKEN)
storage = RedisStorage.from_url(f"redis://{config.REDIS_HOST}:{config.REDIS_PORT}/{config.REDIS_DB}")
dp = Dispatcher(storage=storage)

# Redis client
redis_client = redis.Redis(
    host=config.REDIS_HOST,
    port=config.REDIS_PORT,
    db=config.REDIS_DB,
    decode_responses=True
)

# Encryption setup
cipher_suite = Fernet(config.ENCRYPTION_KEY.encode())

def encrypt_data(data: str) -> str:
    try:
        encrypted = cipher_suite.encrypt(data.encode()).decode()
        logger.info(f"Data encrypted successfully (first 5 chars: {data[:5]}...)")
        return encrypted
    except Exception as e:
        logger.error(f"Encryption failed: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise

def decrypt_data(encrypted_data: str) -> str:
    try:
        decrypted = cipher_suite.decrypt(encrypted_data.encode()).decode()
        logger.info(f"Data decrypted successfully (first 5 chars: {decrypted[:5]}...)")
        return decrypted
    except Exception as e:
        logger.error(f"Decryption failed: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise

# FastAPI app
app = FastAPI(title="METAN.BY Bot Admin Interface")
security = HTTPBasic()
app.add_middleware(SentryAsgiMiddleware)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount("/backups", StaticFiles(directory="backups"), name="backups")
templates = Jinja2Templates(directory="templates")

# Basic auth for web interface
async def get_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = credentials.username == config.WEB_USERNAME
    correct_password = credentials.password == config.WEB_PASSWORD
    
    if not (correct_username and correct_password):
        logger.warning(f"Failed login attempt for username: {credentials.username}")
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# Web routes
@app.get("/logs", response_class=HTMLResponse)
async def logs_ui(request: Request, username: str = Depends(get_current_user)):
    return templates.TemplateResponse("logs.html", {"request": request})

@app.get("/users", response_class=HTMLResponse)
async def users_ui(request: Request, username: str = Depends(get_current_user)):
    return templates.TemplateResponse("users.html", {"request": request})

@app.get("/api/users")
async def get_users(
    search: str = "",
    status: str = "all",
    page: int = 1,
    per_page: int = 10,
    username: str = Depends(get_current_user)
):
    pool = await get_db_connection()
    offset = (page - 1) * per_page
    
    query = "SELECT * FROM users WHERE 1=1"
    params = []
    
    if search:
        query += " AND (username ILIKE $1 OR first_name ILIKE $1 OR last_name ILIKE $1)"
        params.append(f"%{search}%")
    
    if status == "active":
        query += " AND last_activity > NOW() - INTERVAL '7 days'"
    elif status == "inactive":
        query += " AND last_activity <= NOW() - INTERVAL '7 days'"
    
    # Получаем пользователей
    users = await pool.fetch(
        f"{query} ORDER BY last_activity DESC LIMIT ${len(params)+1} OFFSET ${len(params)+2}",
        *params, per_page, offset
    )
    
    # Получаем общее количество
    count = await pool.fetchval(f"SELECT COUNT(*) FROM ({query}) AS subq", *params)
    
    return {
        "users": users,
        "total": count,
        "page": page,
        "per_page": per_page
    }

@app.get("/api/logs")
async def get_logs(
    level: str = "all",
    date_from: str = None,
    date_to: str = None,
    search: str = "",
    page: int = 1,
    per_page: int = 10,
    username: str = Depends(get_current_user)
):
    # В реальном проекте подключите Sentry API или читайте из файла логов
    # Здесь примерная реализация
    logs = []
    try:
        with open("bot.log", "r") as f:
            logs = f.readlines()[-1000:]  # Последние 1000 строк
    except:
        pass
    
    # Фильтрация (упрощенная)
    filtered = []
    for log in logs:
        if level != "all" and level.lower() not in log.lower():
            continue
        if search and search.lower() not in log.lower():
            continue
        filtered.append(log)
    
    # Пагинация
    total = len(filtered)
    paginated = filtered[(page-1)*per_page : page*per_page]
    
    return {
        "logs": paginated,
        "total": total,
        "page": page,
        "per_page": per_page
    }

@app.get("/api/stats")
async def get_stats(
    period: str = "week",  # day/week/month/year
    username: str = Depends(get_current_user)
):
    pool = await get_db_connection()
    
    # Определяем интервал для периода
    intervals = {
        "day": "1 day",
        "week": "1 week",
        "month": "1 month",
        "year": "1 year"
    }
    interval = intervals.get(period, "1 week")

    # 1. Динамика регистраций пользователей
    users_dynamic = await pool.fetch(f"""
        SELECT 
            date_trunc('hour', registered_at) as time_point,
            COUNT(*) as count
        FROM users
        WHERE registered_at >= NOW() - INTERVAL '{interval}'
        GROUP BY time_point
        ORDER BY time_point
    """)

    # 2. Динамика вопросов
    questions_dynamic = await pool.fetch(f"""
        SELECT 
            date_trunc('hour', registered_at) as time_point,
            COUNT(*) as count
        FROM questions
        WHERE created_at >= NOW() - INTERVAL '{interval}'
        GROUP BY time_point
        ORDER BY time_point
    """)

    # 3. Общая статистика
    total_stats = await pool.fetchrow("""
        SELECT
            (SELECT COUNT(*) FROM users) as total_users,
            (SELECT COUNT(*) FROM questions) as total_questions,
            (SELECT COUNT(*) FROM questions WHERE answer IS NOT NULL) as answered_questions,
            (SELECT COUNT(*) FROM contracts_physical) as physical_contracts,
            (SELECT COUNT(*) FROM contracts_legal) as legal_contracts
    """)

    return {
        "dynamics": {
            "users": [{"time": str(r["time_point"]), "count": r["count"]} for r in users_dynamic],
            "questions": [{"time": str(r["time_point"]), "count": r["count"]} for r in questions_dynamic]
        },
        "totals": dict(total_stats)
    }

@app.get("/settings", response_class=HTMLResponse)
async def settings_ui(request: Request, username: str = Depends(get_current_user)):
    pool = await get_db_connection()
    settings = {
        "welcome_message": await pool.fetchval("SELECT value FROM bot_settings WHERE key = 'welcome_message'"),
        "experience_video_link": await pool.fetchval("SELECT value FROM bot_settings WHERE key = 'experience_video_link'"),
        "experience_docs_link": await pool.fetchval("SELECT value FROM bot_settings WHERE key = 'experience_docs_link'"),
    }
    return templates.TemplateResponse("settings.html", {"request": request, "settings": settings})

@app.post("/settings")
async def update_settings(
    welcome_message: str = Form(...),
    experience_video_link: str = Form(...),
    experience_docs_link: str = Form(...),
    username: str = Depends(get_current_user)
):
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO bot_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
            "welcome_message", welcome_message
        )
        await conn.execute(
            "INSERT INTO bot_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
            "experience_video_link", experience_video_link
        )
        await conn.execute(
            "INSERT INTO bot_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = $2",
            "experience_docs_link", experience_docs_link
        )
    
    return RedirectResponse(url="/settings", status_code=303)
	
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request, username: str = Depends(get_current_user)):
    logger.info(f"Web interface accessed by {username}")
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/health")
async def health_check():
    logger.info("Health check requested")
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

@app.get("/backup", response_class=HTMLResponse)
async def backup_ui(request: Request, username: str = Depends(get_current_user)):
    backups = []
    if os.path.exists("backups"):
        backups = sorted(os.listdir("backups"), reverse=True)[:5]
    return templates.TemplateResponse("backup.html", {
        "request": request,
        "backups": backups
    })

@app.post("/backup")
async def create_backup_ui(username: str = Depends(get_current_user)):
    try:
        os.makedirs("backups", exist_ok=True)
        backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M')}.sql"
        backup_path = f"backups/{backup_name}"
        
        # Используем синхронный subprocess.run
        result = subprocess.run(
            f"pg_dump {config.POSTGRES_DSN} > {backup_path}",
            shell=True,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            raise RuntimeError(result.stderr)
            
        return RedirectResponse(url="/backup", status_code=303)
        
    except Exception as e:
        logger.error(f"Backup failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Backup creation failed: {str(e)}"
        )
        
@app.get("/export", response_class=HTMLResponse)
async def export_data(request: Request, username: str = Depends(get_current_user)):
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        data = {
            "questions": await conn.fetchval("SELECT COUNT(*) FROM questions"),
            "contracts": await conn.fetchval("SELECT COUNT(*) FROM contracts_physical") + 
                        await conn.fetchval("SELECT COUNT(*) FROM contracts_legal")
        }
    return templates.TemplateResponse("export.html", {
        "request": request,
        "data": data
    })
    
@app.get("/export/questions.csv")
async def export_questions_csv(username: str = Depends(get_current_user)):
    csv_path = await export_questions_to_csv()
    if not csv_path:
        raise HTTPException(
            status_code=404,
            detail="No questions found or export failed"
        )
    
    # Проверяем размер файла
    if os.path.getsize(csv_path) == 0:
        raise HTTPException(
            status_code=404,
            detail="Exported file is empty"
        )
    
    return FileResponse(
        csv_path,
        filename="questions.csv",
        media_type="text/csv"
    )

@app.get("/export/physical_contracts.csv")
async def export_physical_contracts_csv(username: str = Depends(get_current_user)):
    csv_path = await export_physical_contracts_to_csv()
    if not csv_path:
        raise HTTPException(
            status_code=404,
            detail="No physical contracts found or export failed"
        )
    
    # Проверяем размер файла
    if os.path.getsize(csv_path) == 0:
        raise HTTPException(
            status_code=404,
            detail="Exported file is empty"
        )
    
    return FileResponse(
        csv_path,
        filename="physical_contracts.csv",
        media_type="text/csv"
    )

@app.get("/export/legal_contracts.csv")
async def export_legal_contracts_csv(username: str = Depends(get_current_user)):
    csv_path = await export_legal_contracts_to_csv()
    if not csv_path:
        raise HTTPException(
            status_code=404,
            detail="No legal contracts found or export failed"
        )
    
    # Проверяем размер файла
    if os.path.getsize(csv_path) == 0:
        raise HTTPException(
            status_code=404,
            detail="Exported file is empty"
        )
    
    return FileResponse(
        csv_path,
        filename="legal_contracts.csv",
        media_type="text/csv"
    )

@app.get("/stats", response_class=HTMLResponse)
async def get_stats(request: Request, username: str = Depends(get_current_user)):
    logger.info(f"Stats requested by {username}")
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            stats = {
                "users": await conn.fetchval("SELECT COUNT(*) FROM users"),
                "questions": await conn.fetchval("SELECT COUNT(*) FROM questions"),
                "answered_questions": await conn.fetchval("SELECT COUNT(*) FROM questions WHERE answer IS NOT NULL"),
                "physical_contracts": await conn.fetchval("SELECT COUNT(*) FROM contracts_physical"),
                "legal_contracts": await conn.fetchval("SELECT COUNT(*) FROM contracts_legal"),
            }
        
        return templates.TemplateResponse("stats.html", {
            "request": request,
            "stats": stats,
            "last_update": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception as e:
        logger.error(f"Failed to get stats: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise HTTPException(status_code=500, detail=str(e))

# Emoji constants
EMOJI_NEW = "🆕"
EMOJI_DONE = "✅"
EMOJI_WARNING = "⚠️"
EMOJI_ERROR = "❌"
EMOJI_INFO = "ℹ️"
EMOJI_QUESTION = "❓"
EMOJI_CONTRACT = "📝"
EMOJI_DOCS = "📄"
EMOJI_MONEY = "💰"
EMOJI_VIDEO = "🎥"
EMOJI_BOOK = "📚"

# Database connection pool
db_pool = None

async def get_db_connection():
    global db_pool
    if db_pool is None:
        try:
            db_pool = await asyncpg.create_pool(dsn=config.POSTGRES_DSN)
            logger.info("Database connection pool created")
        except Exception as e:
            logger.error(f"Failed to create database pool: {e}", exc_info=True)
            sentry_sdk.capture_exception(e)
            raise
    return db_pool

# Validation functions
def validate_phone(phone: str) -> str:
    logger.info(f"Validating phone: {phone[:5]}...")
    if not phone.startswith('+375') or len(phone) != 13 or not phone[1:].isdigit():
        logger.warning(f"Invalid phone format: {phone}")
        raise ValueError('Телефон должен быть в формате +375XXXXXXXXX')
    return phone

def validate_email(email: str) -> str:
    logger.info(f"Validating email: {email[:5]}...")
    try:
        validated = EmailStr._validate(email)
        logger.info("Email validation successful")
        return validated
    except ValueError as e:
        logger.warning(f"Invalid email format: {email}")
        raise ValueError('Неверный формат email') from e

def validate_unp(unp: str) -> str:
    logger.info(f"Validating UNP: {unp[:5]}...")
    if len(unp) != 9 or not unp.isdigit():
        logger.warning(f"Invalid UNP format: {unp}")
        raise ValueError('УНП должен состоять из 9 цифр')
    return unp

def validate_okpo(okpo: str) -> str:
    logger.info(f"Validating OKPO: {okpo[:5]}...")
    if okpo.lower() == '➡️ пропустить':  # Добавляем возможность пропустить
        return ''
    if len(okpo) != 8 or not okpo.isdigit():
        logger.warning(f"Invalid OKPO format: {okpo}")
        raise ValueError('ОКПО должен состоять из 8 цифр или напишите "пропустить"')
    return okpo

def validate_account(account: str) -> str:
    logger.info(f"Validating account: {account[:10]}...")
    if not account.startswith('IBAN BY') or len(account) < 16:
        logger.warning(f"Invalid account format: {account}")
        raise ValueError('Расчетный счет должен начинаться с IBAN BY...')
    return account

def validate_passport_date(date_str: str) -> str:
    logger.info(f"Validating passport date: {date_str}")
    try:
        datetime.strptime(date_str, "%d.%m.%Y")
        logger.info("Passport date validation successful")
        return date_str
    except ValueError:
        logger.warning(f"Invalid passport date format: {date_str}")
        raise ValueError('Неверный формат даты. Используйте ДД.ММ.ГГГГ')

def sanitize_input(text: str) -> str:
    if not text:
        return text
    
    sanitized = re.sub(r'([\'";\\])', r'\\\1', text)
    sanitized = html.escape(sanitized)
    logger.info(f"Input sanitized (original: {text[:20]}..., sanitized: {sanitized[:20]}...)")
    return sanitized

# Pydantic models
class BotSettings(BaseModel):
    welcome_message: str
    experience_video_link: str
    experience_docs_link: str

class UserFilter(BaseModel):
    search: str = ""
    status: str = "all"
    page: int = 1
    per_page: int = 10
	
class PhysicalPersonData(BaseModel):
    full_name: str
    passport_id: str
    passport_issue_date: str
    passport_issued_by: str
    living_address: str
    registration_address: Optional[str] = None
    phone: str
    email: EmailStr

    @field_validator('*')
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        if isinstance(v, str):
            return sanitize_input(v)
        return v

    @field_validator('phone')
    @classmethod
    def phone_validator(cls, v: str) -> str:
        return validate_phone(v)

    @field_validator('email')
    @classmethod
    def email_validator(cls, v: str) -> str:
        return validate_email(v)

    @field_validator('passport_issue_date')
    @classmethod
    def date_validator(cls, v: str) -> str:
        return validate_passport_date(v)

class LegalPersonData(BaseModel):
    organization_name: str
    postal_address: str
    legal_address: Optional[str] = None
    phone: str
    activity_type: str
    okpo: Optional[str] = None
    unp: str
    account_number: str
    bank_name: str
    bank_bic: str
    bank_address: str
    signatory_name: str
    authority_basis: str
    position: str
    email: EmailStr

    @field_validator('*')
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        if isinstance(v, str):
            return sanitize_input(v)
        return v

    @field_validator('account_number')
    @classmethod
    def account_validator(cls, v: str) -> str:
        return validate_account(v)

    @field_validator('unp')
    @classmethod
    def unp_validator(cls, v: str) -> str:
        return validate_unp(v)

    @field_validator('okpo')
    @classmethod
    def okpo_validator(cls, v: str) -> Optional[str]:
        if v is None or v == '':  # Разрешаем None или пустую строку
            return None
        return validate_okpo(v)
		
    @field_validator('email')
    @classmethod
    def email_validator(cls, v: str) -> str:
        return validate_email(v)

# States for FSM
class Form(StatesGroup):
    # Physical person states
    physical_full_name = State()
    physical_passport_id = State()
    physical_passport_issue_date = State()
    physical_passport_issued_by = State()
    physical_living_address = State()
    physical_registration_address = State()
    physical_phone = State()
    physical_email = State()
    physical_confirm = State()
    
    # Legal person states
    legal_organization_name = State()
    legal_postal_address = State()
    legal_legal_address = State()
    legal_phone = State()
    legal_activity_type = State()
    legal_okpo = State()
    legal_unp = State()
    legal_account_number = State()
    legal_bank_name = State()
    legal_bank_bic = State()
    legal_bank_address = State()
    legal_signatory_name = State()
    legal_authority_basis = State()
    legal_position = State()
    legal_email = State()
    legal_confirm = State()

    # Question states
    waiting_for_question = State()
    waiting_for_answer = State()

# Добавим в StatesGroup
class DelayedMessageStates(StatesGroup):
    waiting_for_content = State()
    waiting_for_text = State()
    waiting_for_photo = State()
    waiting_for_time = State()
    waiting_for_recipients = State()
    waiting_for_user_id = State()

# Database initialization
async def init_db():
    logger.info("Initializing database...")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                username TEXT,
                question TEXT NOT NULL,
                answer TEXT,
                answered_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                answered_at TIMESTAMP,
                skipped_at TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS questions_user_id_idx ON questions(user_id);
            CREATE INDEX IF NOT EXISTS questions_answered_idx ON questions(answered_at) WHERE answered_at IS NOT NULL;
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS contracts_physical (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                username TEXT,
                full_name TEXT NOT NULL,
                passport_id TEXT NOT NULL,
                passport_issue_date TEXT NOT NULL,
                passport_issued_by TEXT NOT NULL,
                living_address TEXT NOT NULL,
                registration_address TEXT,
                phone TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            );
            CREATE INDEX IF NOT EXISTS contracts_physical_user_id_idx ON contracts_physical(user_id);
            CREATE INDEX IF NOT EXISTS contracts_physical_status_idx ON contracts_physical(status);
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS contracts_legal (
                id SERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                username TEXT,
                organization_name TEXT NOT NULL,
                postal_address TEXT NOT NULL,
                legal_address TEXT,
                phone TEXT NOT NULL,
                activity_type TEXT NOT NULL,
                okpo TEXT,
                unp TEXT NOT NULL,
                account_number TEXT NOT NULL,
                bank_name TEXT NOT NULL,
                bank_bic TEXT NOT NULL,
                bank_address TEXT NOT NULL,
                signatory_name TEXT NOT NULL,
                authority_basis TEXT NOT NULL,
                position TEXT NOT NULL,
                email TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'pending'
            );
            CREATE INDEX IF NOT EXISTS contracts_legal_user_id_idx ON contracts_legal(user_id);
            CREATE INDEX IF NOT EXISTS contracts_legal_status_idx ON contracts_legal(status);
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS bot_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """)
            
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                last_name TEXT,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS users_username_idx ON users(username);
            """)
			

            await conn.execute("""
            CREATE TABLE IF NOT EXISTS delayed_messages (
                id SERIAL PRIMARY KEY,
                content_type TEXT NOT NULL,  -- 'text', 'photo', 'photo_with_text'
                text_content TEXT,
                photo_path TEXT,
                send_time TIMESTAMP NOT NULL,
                status TEXT NOT NULL,  -- 'pending', 'approved', 'rejected', 'sent', 'failed', 'blocked'
                recipient_type TEXT NOT NULL,  -- 'all', 'moderators', 'specific'
                recipient_id BIGINT,
                created_by BIGINT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                approved_by BIGINT,
				attempts INTEGER DEFAULT 0,
                approved_at TIMESTAMP
            );
            """)
			
            await conn.execute("""
            CREATE TABLE IF NOT EXISTS bot_settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """)
        
            # Добавляем начальные настройки
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('welcome_message', 'Добро пожаловать в бот METAN.BY!'),
                ('experience_video_link', 'https://example.com/video'),
                ('experience_docs_link', 'https://example.com/docs')
            ON CONFLICT (key) DO NOTHING
            """)
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('button_unanswered_questions', '1'),
                ('button_view_contracts', '1'),
                ('button_delayed_messages', '1')
            ON CONFLICT (key) DO NOTHING
            """)
			
            await conn.execute("""
            INSERT INTO bot_settings (key, value) VALUES 
                ('notify_admin_questions', '1'),
                ('notify_admin_contracts', '1'),
                ('notify_admin_errors', '1'),
                ('notify_moderators_questions', '1'),
                ('notify_moderators_contracts', '1')
            ON CONFLICT (key) DO NOTHING
            """)
            
            logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise

# Helper functions
async def is_admin(user_id: int) -> bool:
    result = user_id == config.ADMIN_ID
    logger.info(f"Checking admin status for {user_id}: {result}")
    return result

async def is_moderator(user_id: int) -> bool:
    result = user_id in config.MODERATOR_IDS or await is_admin(user_id)
    logger.info(f"Checking moderator status for {user_id}: {result}")
    return result

async def is_button_enabled(button_key: str) -> bool:
    logger.info(f"Checking button status for {button_key}")
    cached = redis_client.get(f"button:{button_key}")
    if cached is not None:
        logger.info(f"Button {button_key} status from cache: {cached == '1'}")
        return cached == "1"
    
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            result = await conn.fetchrow(
                "SELECT value FROM bot_settings WHERE key = $1",
                button_key
            )
            enabled = result and result['value'] == '1' if result else True
            logger.info(f"Button {button_key} status from DB: {enabled}")
        
        redis_client.setex(f"button:{button_key}", 300, "1" if enabled else "0")
        return enabled
    except Exception as e:
        logger.error(f"Failed to check button status for {button_key}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return True

async def notify_admins(text: str, emoji: str = EMOJI_INFO, notification_type: str = "info"):
    """Отправка уведомлений админу с проверкой настроек"""
    try:
        # Проверяем, нужно ли отправлять уведомление этого типа
        if notification_type == "question" and not await is_notification_enabled('notify_admin_questions'):
            logger.info("Уведомления о вопросах для админа отключены")
            return
        if notification_type == "contract" and not await is_notification_enabled('notify_admin_contracts'):
            logger.info("Уведомления о договорах для админа отключены")
            return
        if notification_type == "error" and not await is_notification_enabled('notify_admin_errors'):
            logger.info("Уведомления об ошибках для админа отключены")
            return

        await bot.send_message(config.ADMIN_ID, f"{emoji} {text}")
        logger.info(f"Уведомление отправлено админу ({notification_type})")
    except Exception as e:
        logger.error(f"Ошибка уведомления админа: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)

async def notify_moderators(text: str, emoji: str = EMOJI_INFO, notification_type: str = "info"):
    """Отправка уведомлений модераторам с проверкой настроек"""
    # Проверяем глобальную настройку для модераторов
    if notification_type == "question" and not await is_notification_enabled('notify_moderators_questions'):
        logger.info("Уведомления о вопросах для модераторов отключены")
        return
    if notification_type == "contract" and not await is_notification_enabled('notify_moderators_contracts'):
        logger.info("Уведомления о договорах для модераторов отключены")
        return

    tasks = []
    for mod_id in config.MODERATOR_IDS:
        try:
            tasks.append(bot.send_message(mod_id, f"{emoji} {text}"))
            logger.info(f"Уведомление отправлено модератору {mod_id} ({notification_type})")
        except Exception as e:
            logger.error(f"Ошибка уведомления модератора {mod_id}: {e}")
    
    await asyncio.gather(*tasks, return_exceptions=True)

async def is_notification_enabled(setting_key: str) -> bool:
    logger.info(f"Checking notification status for {setting_key}")
    cached = redis_client.get(f"notification:{setting_key}")
    if cached is not None:
        logger.info(f"Notification {setting_key} status from cache: {cached == '1'}")
        return cached == "1"
    
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            result = await conn.fetchrow(
                "SELECT value FROM bot_settings WHERE key = $1",
                setting_key
            )
            enabled = result and result['value'] == '1' if result else True
            logger.info(f"Notification {setting_key} status from DB: {enabled}")
        
        redis_client.setex(f"notification:{setting_key}", 300, "1" if enabled else "0")
        return enabled
    except Exception as e:
        logger.error(f"Failed to check notification status for {setting_key}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return True

async def get_user_mention(user: types.User) -> str:
    mention = f"@{user.username}" if user.username else f"[{user.full_name}](ID: {user.id})"
    logger.info(f"Generated mention for user {user.id}: {mention[:20]}...")
    return mention

async def export_to_csv(data: List[Dict], filename: str) -> Optional[str]:
    logger.info(f"Exporting data to CSV: {filename}")
    try:
        csv_path = f"temp/{filename}"
        os.makedirs("temp", exist_ok=True)
        
        if not data:
            logger.warning(f"No data to export for {filename}")
            return None
        
        keys = data[0].keys()
        
        with open(csv_path, mode='w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(data)
        
        if not os.path.exists(csv_path):
            logger.error(f"Failed to create file: {csv_path}")
            return None
            
        logger.info(f"CSV export successful: {csv_path}")
        return csv_path
    except Exception as e:
        logger.error(f"Export to CSV failed: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return None

async def cleanup_temp_files():
    logger.info("Cleaning up temp files")
    try:
        if os.path.exists("temp"):
            for filename in os.listdir("temp"):
                file_path = os.path.join("temp", filename)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                        logger.info(f"Deleted temp file: {filename}")
                except Exception as e:
                    logger.error(f"Failed to delete {file_path}: {e}", exc_info=True)
                    sentry_sdk.capture_exception(e)
    except Exception as e:
        logger.error(f"Cleanup error: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)

async def check_disk_space() -> bool:
    logger.info("Checking disk space")
    try:
        if hasattr(os, 'statvfs'):
            stat = os.statvfs('/')
            free_space_gb = (stat.f_bavail * stat.f_frsize) / (1024 ** 3)
        else:
            usage = shutil.disk_usage('C:\\')
            free_space_gb = usage.free / (1024 ** 3)
        
        MINIMUM_SPACE_GB = 1
        if free_space_gb < MINIMUM_SPACE_GB:
            logger.warning(f"Low disk space: {free_space_gb:.2f}GB")
            return False
        logger.info(f"Disk space OK: {free_space_gb:.2f}GB free")
        return True
    except Exception as e:
        logger.error(f"Disk space check failed: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return False

async def send_document_safe(message: types.Message, file_path: str, filename: str):
    logger.info(f"Sending document: {filename} from {file_path}")
    try:
        file_size = os.path.getsize(file_path) / (1024 * 1024)
        if file_size > 50:
            logger.warning(f"File too large: {file_size:.2f}MB")
            await message.answer(f"Файл {filename} слишком большой ({file_size:.2f}MB). Максимальный размер: 50MB")
            return
        
        with open(file_path, 'rb') as file:
            await message.answer_document(
                BufferedInputFile(file.read(), filename=filename))
        logger.info("Document sent successfully")
    except Exception as e:
        logger.error(f"Failed to send document {filename}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer(f"Ошибка при отправке файла {filename}: {str(e)}")

async def export_questions_to_csv() -> Optional[str]:
    logger.info("Exporting questions to CSV")
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            questions = await conn.fetch(
                "SELECT id, user_id, username, question, answer, answered_by, created_at, answered_at, skipped_at FROM questions"
            )
            
            if not questions:
                logger.warning("No questions to export")
                return None
            
            questions_data = []
            for q in questions:
                questions_data.append({
                    "id": q['id'],
                    "user_id": q['user_id'],
                    "username": q['username'] or "",
                    "question": q['question'],
                    "answer": q['answer'] or "",
                    "answered_by": q['answered_by'] or "",
                    "created_at": q['created_at'],
                    "answered_at": q['answered_at'] or "",
                    "skipped_at": q['skipped_at'] or ""
                })
            
            return await export_to_csv(questions_data, "questions.csv")
    except Exception as e:
        logger.error(f"Failed to export questions: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return None

async def export_physical_contracts_to_csv() -> Optional[str]:
    logger.info("Exporting physical contracts to CSV")
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            contracts = await conn.fetch("SELECT * FROM contracts_physical")
            
            if not contracts:
                logger.warning("No physical contracts to export")
                return None
            
            contracts_data = []
            for c in contracts:
                contracts_data.append({
                    'id': c['id'],
                    'user_id': c['user_id'],
                    'username': c['username'],
                    'full_name': c['full_name'],
                    'passport_id': decrypt_data(c['passport_id']),
                    'passport_issue_date': c['passport_issue_date'],
                    'passport_issued_by': c['passport_issued_by'],
                    'living_address': c['living_address'],
                    'registration_address': c['registration_address'],
                    'phone': decrypt_data(c['phone']),
                    'email': c['email'],
                    'created_at': c['created_at'],
                    'status': c['status']
                })
            
            return await export_to_csv(contracts_data, "physical_contracts.csv")
    except Exception as e:
        logger.error(f"Failed to export physical contracts: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return None

async def export_legal_contracts_to_csv() -> Optional[str]:
    logger.info("Exporting legal contracts to CSV")
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            contracts = await conn.fetch("SELECT * FROM contracts_legal")
            
            if not contracts:
                logger.warning("No legal contracts to export")
                return None
            
            contracts_data = []
            for c in contracts:
                try:
                    # Initialize with NULL/None values
                    contract_data = {
                        'id': c['id'],
                        'user_id': c['user_id'],
                        'username': c['username'],
                        'organization_name': c['organization_name'],
                        'postal_address': c['postal_address'],
                        'legal_address': c['legal_address'],
                        'phone': None,
                        'activity_type': c['activity_type'],
                        'okpo': None,
                        'unp': None,
                        'account_number': None,
                        'bank_name': c['bank_name'],
                        'bank_bic': c['bank_bic'],
                        'bank_address': c['bank_address'],
                        'signatory_name': c['signatory_name'],
                        'authority_basis': c['authority_basis'],
                        'position': c['position'],
                        'email': c['email'],
                        'created_at': c['created_at'],
                        'status': c['status']
                    }
                    
                    # Decrypt each field separately with error handling
                    try:
                        if c['phone']:
                            contract_data['phone'] = decrypt_data(c['phone'])
                    except Exception as e:
                        logger.error(f"Failed to decrypt phone for contract {c['id']}: {e}")
                        contract_data['phone'] = "[decryption error]"
                    
                    try:
                        if c['okpo']:
                            contract_data['okpo'] = decrypt_data(c['okpo'])
                    except Exception as e:
                        logger.error(f"Failed to decrypt okpo for contract {c['id']}: {e}")
                        contract_data['okpo'] = "[decryption error]"
                    
                    try:
                        if c['unp']:
                            contract_data['unp'] = decrypt_data(c['unp'])
                    except Exception as e:
                        logger.error(f"Failed to decrypt unp for contract {c['id']}: {e}")
                        contract_data['unp'] = "[decryption error]"
                    
                    try:
                        if c['account_number']:
                            contract_data['account_number'] = decrypt_data(c['account_number'])
                    except Exception as e:
                        logger.error(f"Failed to decrypt account_number for contract {c['id']}: {e}")
                        contract_data['account_number'] = "[decryption error]"
                    
                    contracts_data.append(contract_data)
                    
                except Exception as e:
                    logger.error(f"Failed to process contract {c['id']}: {e}")
                    continue
            
            if not contracts_data:
                logger.warning("No valid contracts to export after processing")
                return None
            
            return await export_to_csv(contracts_data, "legal_contracts.csv")
            
    except Exception as e:
        logger.error(f"Failed to export legal contracts: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return None

async def get_all_users_count() -> int:
    logger.info("Getting users count")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            result = await conn.fetchval("SELECT COUNT(*) FROM users")
            logger.info(f"Total users: {result}")
            return result if result else 0
    except Exception as e:
        logger.error(f"Failed to get users count: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        return 0

async def register_user(user: types.User):
    logger.info(f"Registering user {user.id}")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO users (user_id, username, first_name, last_name) VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO NOTHING",
                user.id, user.username, user.first_name, user.last_name
            )
            await conn.execute(
                "UPDATE users SET last_activity = CURRENT_TIMESTAMP WHERE user_id = $1",
                user.id
            )
        logger.info(f"User {user.id} registered/updated")
    except Exception as e:
        logger.error(f"Failed to register user {user.id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        raise

# Keyboard builders
async def get_main_menu(user_id: int) -> types.ReplyKeyboardMarkup:
    logger.info(f"Generating main menu for user {user_id}")
    builder = ReplyKeyboardBuilder()
    
    if await is_button_enabled('button_consultation'):
        builder.button(text=f"{EMOJI_QUESTION} Консультация со специалистом")
    
    if await is_button_enabled('button_roi'):
        builder.button(text=f"{EMOJI_MONEY} Расчёт окупаемости")
    
    if await is_button_enabled('button_experience'):
        builder.button(text=f"{EMOJI_VIDEO}{EMOJI_BOOK}Полезная информация")
    
    if await is_button_enabled('button_contract'):
        builder.button(text=f"{EMOJI_CONTRACT} Заключение договора")
    
    if await is_moderator(user_id):
        builder.button(text="🔧 Модераторское меню")
    
    if await is_admin(user_id):
        builder.button(text="👑 Админ-панель")
    
    builder.adjust(2, 2, 1, 1)
    return builder.as_markup(resize_keyboard=True)

async def get_experience_menu() -> types.InlineKeyboardMarkup:
    logger.info("Generating experience menu")
    builder = InlineKeyboardBuilder()
    builder.button(text=f"{EMOJI_VIDEO} Видеоматериалы", callback_data="experience_video")
    builder.button(text=f"{EMOJI_BOOK} Печатные издания", callback_data="experience_print")
    builder.button(text="⬅️ Назад", callback_data="main_menu")
    builder.adjust(2, 1)
    return builder.as_markup()

async def get_contract_type_menu() -> types.InlineKeyboardMarkup:
    logger.info("Generating contract type menu")
    builder = InlineKeyboardBuilder()
    builder.button(text="Физическое лицо", callback_data="contract_physical")
    builder.button(text="Юридическое лицо", callback_data="contract_legal")
    builder.button(text="⬅️ Назад", callback_data="main_menu")
    builder.adjust(2, 1)
    return builder.as_markup()

async def get_cancel_keyboard() -> types.ReplyKeyboardMarkup:
    logger.info("Generating cancel keyboard")
    builder = ReplyKeyboardBuilder()
    builder.button(text="❌ Отменить заполнение")
    return builder.as_markup(resize_keyboard=True)

# Добавим в get_moderator_menu()
async def get_moderator_menu() -> types.ReplyKeyboardMarkup:
    builder = ReplyKeyboardBuilder()
    
    # Проверяем, включена ли кнопка вопросов
    if await is_button_enabled('button_unanswered_questions'):
        builder.button(text="📋 Неотвеченные вопросы")
    
    # Проверяем, включена ли кнопка договоров
    if await is_button_enabled('button_view_contracts'):
        builder.button(text="📝 Просмотреть договоры")
    
    # Проверяем, включена ли кнопка отложенных сообщений
    if await is_button_enabled('button_delayed_messages'):
        builder.button(text="⏱ Создать отложенное сообщение")
    
    builder.button(text="⬅️ Главное меню")
    builder.adjust(2, 1, 1)
    return builder.as_markup(resize_keyboard=True)

async def get_admin_menu() -> types.ReplyKeyboardMarkup:
    builder = ReplyKeyboardBuilder()
    builder.button(text="📊 Статистика")
    builder.button(text="📁 Экспорт данных")
    builder.button(text="🗃 Управление хранилищем")
    builder.button(text="🔔 Управление уведомлениями")
    builder.button(text="🛠 Управление кнопками")
    builder.button(text="⏱ Управление отлож. сообщениями")
    builder.button(text="⬅️ Главное меню")
    builder.adjust(2, 2, 2, 1)
    return builder.as_markup(resize_keyboard=True)

async def get_question_action_menu(question_id: int, has_next: bool = False, has_prev: bool = False) -> types.InlineKeyboardMarkup:
    logger.info(f"Generating question action menu for question {question_id}")
    builder = InlineKeyboardBuilder()
    builder.button(text="💪🏾 Ответить", callback_data=f"answer_{question_id}")
    builder.button(text="🙈 Пропустить", callback_data=f"skip_{question_id}")
    
    # Add navigation buttons if needed
    if has_prev:
        builder.button(text="⬅️ Предыдущий", callback_data=f"prev_question_{question_id}")
    if has_next:
        builder.button(text="➡️ Следующий", callback_data=f"next_question_{question_id}")
    
    builder.button(text="👀 Скрыть", callback_data="cancel_question")
    builder.adjust(2, 2, 1)
    return builder.as_markup()

async def get_confirm_menu(confirm_data: str) -> types.InlineKeyboardMarkup:
    logger.info(f"Generating confirm menu for {confirm_data}")
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Подтвердить", callback_data=f"confirm_{confirm_data}")
    builder.button(text="❌ Отменить", callback_data="cancel_confirm")
    return builder.as_markup()

async def get_cancel_reply_keyboard() -> types.ReplyKeyboardMarkup:
    logger.info("Generating cancel reply keyboard")
    builder = ReplyKeyboardBuilder()
    builder.button(text="❌ Отменить ответ")
    return builder.as_markup(resize_keyboard=True)

async def get_contract_action_menu(contract_id: int, contract_type: str, has_next: bool = False, has_prev: bool = False) -> types.InlineKeyboardMarkup:
    logger.info(f"Generating contract action menu for {contract_type} contract {contract_id}")
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Обработать", callback_data=f"process_contract_{contract_type}_{contract_id}")
    builder.button(text="🚫 Скрыть", callback_data=f"hide_contract_{contract_type}_{contract_id}")
    
    # Add navigation buttons if needed
    if has_prev:
        builder.button(text="⬅️ Предыдущий", callback_data=f"prev_contract_{contract_type}_{contract_id}")
    if has_next:
        builder.button(text="➡️ Следующий", callback_data=f"next_contract_{contract_type}_{contract_id}")
    
    builder.adjust(2, 2)
    return builder.as_markup()

# Command handlers
@dp.message(F.text == "❌ Отменить заполнение")
async def cancel_filling_handler(message: types.Message, state: FSMContext):
    logger.info(f"User {message.from_user.id} canceled form filling")
    await state.clear()
    await message.answer(
        "Заполнение отменено.",
        reply_markup=await get_main_menu(message.from_user.id)
    )
	
@dp.message(Command("start"))
async def cmd_start(message: types.Message):
    logger.info(f"User {message.from_user.id} started the bot")
    try:
        await register_user(message.from_user)
        await message.answer(
            "Команда METAN.BY приветствует Вас!",
            reply_markup=await get_main_menu(message.from_user.id)
        )
        logger.info(f"Successfully processed start command for user {message.from_user.id}")
    except Exception as e:
        logger.error(f"Error in start command for user {message.from_user.id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при обработке команды. Пожалуйста, попробуйте позже.")

@dp.message(Command("help"))
async def cmd_help(message: types.Message):
    logger.info(f"User {message.from_user.id} requested help")
    help_text = (
        "📌 Доступные функции:\n"
        f"{EMOJI_QUESTION} Консультация со специалистом - задайте вопрос и получите ответ\n"
        f"{EMOJI_MONEY} Расчёт окупаемости - калькулятор окупаемости (в разработке)\n"
        f"{EMOJI_VIDEO}{EMOJI_BOOK}Полезная информация - доступ к видеоматериалам и печатным руководствам\n"
        f"{EMOJI_CONTRACT} Заключение договора - оформление договора для физ. или юр. лиц"
    )
    await message.answer(help_text)

# Main menu handlers
@dp.message(F.text == f"{EMOJI_QUESTION} Консультация со специалистом")
async def consultation_handler(message: types.Message, state: FSMContext):
    logger.info(f"User {message.from_user.id} requested consultation")
    cancel_kb = ReplyKeyboardBuilder()
    cancel_kb.button(text="❌ Отменить вопрос")
    cancel_kb.adjust(1)
    
    await message.answer(
        "Пожалуйста, напишите ваш вопрос. Мы постараемся ответить как можно скорее.\n"
        "Вы можете отменить вопрос, нажав кнопку ниже.",
        reply_markup=cancel_kb.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.waiting_for_question)

@dp.message(Form.waiting_for_question, F.text == "❌ Отменить вопрос")
async def cancel_question_handler(message: types.Message, state: FSMContext):
    logger.info(f"User {message.from_user.id} canceled question")
    await message.answer(
        "Вопрос отменен.",
        reply_markup=await get_main_menu(message.from_user.id)
    )
    await state.clear()

@dp.message(Form.waiting_for_question)
async def process_question(message: types.Message, state: FSMContext):
    question = sanitize_input(message.text)
    user = message.from_user
    
    logger.info(f"Processing question from user {user.id}: {question[:50]}...")
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO questions (user_id, username, question) VALUES ($1, $2, $3)",
                user.id, user.username, question
            )
            logger.info(f"Question from user {user.id} saved to database")
    except Exception as e:
        logger.error(f"Failed to save question from user {user.id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при сохранении вопроса. Пожалуйста, попробуйте позже.")
        return
    
    user_mention = await get_user_mention(user)
    admin_text = f"{EMOJI_NEW} Новый вопрос от {user_mention}\n\n{question}"
    moderator_text = f"{EMOJI_NEW} Новый вопрос (ID: {user.id})\n\n{question}"
    
    await notify_admins(admin_text, EMOJI_QUESTION, notification_type="question")
    await notify_moderators(moderator_text, EMOJI_QUESTION, notification_type="question")
    
    await message.answer(
        "Ваш вопрос получен и передан специалисту. Мы ответим вам как можно скорее.",
        reply_markup=await get_main_menu(user.id)
    )
    await state.clear()
    logger.info(f"Question from user {user.id} processed successfully")

@dp.message(F.text == f"{EMOJI_MONEY} Расчёт окупаемости")
async def roi_handler(message: types.Message):
    logger.info(f"User {message.from_user.id} requested ROI calculation")
    await message.answer(
        "Функция расчета окупаемости в разработке. Скоро будет доступна!",
        reply_markup=await get_main_menu(message.from_user.id)
    )

@dp.message(F.text == f"{EMOJI_VIDEO}{EMOJI_BOOK}Полезная информация")
async def experience_handler(message: types.Message):
    logger.info(f"User {message.from_user.id} requested experience materials")
    await message.answer(
        "Выберите тип материалов:",
        reply_markup=await get_experience_menu()
    )

@dp.callback_query(F.data == "experience_video")
async def experience_video_handler(callback: types.CallbackQuery):
    logger.info(f"User {callback.from_user.id} selected video materials")
    
    # Формируем новый текст
    text_lines = [
        r"🎥\ *Видеоматериалы по эксплуатации:*",
        "",
        r"1\. [Основные принципы работы](https://example\.com/video1)",
        r"2\. [Техническое обслуживание](https://example\.com/video2)", 
        r"3\. [Частые проблемы и решения](https://example\.com/video3)",
        ""
    ]
    new_text = "\n".join(text_lines)
    
    # Получаем новую клавиатуру
    new_markup = await get_experience_menu()
    
    # Получаем текущие параметры сообщения
    current_text = callback.message.text
    current_markup = callback.message.reply_markup
    
    try:
        # Проверяем, есть ли реальные изменения
        if current_text != new_text or str(current_markup) != str(new_markup):
            await callback.message.edit_text(
                new_text,
                parse_mode="MarkdownV2",
                reply_markup=new_markup
            )
        else:
            await callback.answer("Уже отображаются видеоматериалы")
            return
            
    except TelegramBadRequest as e:
        if "message is not modified" in str(e):
            await callback.answer("Уже отображаются видеоматериалы")
        else:
            logger.error(f"Telegram API error: {e}")
            await callback.answer("Ошибка при обновлении", show_alert=True)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        await callback.answer("Произошла ошибка", show_alert=True)
    finally:
        await callback.answer()

@dp.callback_query(F.data == "experience_print")
async def experience_print_handler(callback: types.CallbackQuery):
    logger.info(f"User {callback.from_user.id} selected print materials")
    
    # Экранируем все спецсимволы MarkdownV2
    text_lines = [
        r"📚 *Печатные материалы по эксплуатации:*",
        "",
        r"1\. [Руководство пользователя](https://example\.com/manual\.pdf)",
        r"2\. [Технический паспорт](https://example\.com/passport\.pdf)",
        r"3\. [Сертификаты соответствия](https://example\.com/certificates\.pdf)"
    ]
    new_text = "\n".join(text_lines)
    
    # Получаем новую клавиатуру
    new_markup = await get_experience_menu()
    
    # Получаем текущие параметры сообщения
    current_text = callback.message.text
    current_markup = callback.message.reply_markup
    
    try:
        # Проверяем, есть ли реальные изменения
        if current_text != new_text or str(current_markup) != str(new_markup):
            await callback.message.edit_text(
                new_text,
                parse_mode="MarkdownV2",
                reply_markup=new_markup
            )
        else:
            await callback.answer("Уже отображаются печатные издания")
            return
            
    except TelegramBadRequest as e:
        if "message is not modified" in str(e):
            await callback.answer("Уже отображаются печатные издания")
        else:
            logger.error(f"Telegram API error: {e}")
            await callback.answer("Ошибка при обновлении", show_alert=True)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        await callback.answer("Произошла ошибка", show_alert=True)
    finally:
        await callback.answer()

@dp.callback_query(F.data == "main_menu")
async def back_to_main_menu_handler(callback: types.CallbackQuery):
    logger.info(f"User {callback.from_user.id} returned to main menu")
    await callback.message.edit_text(
        "Возвращаемся в главное меню",
        reply_markup=None
    )
    await callback.message.answer(
        "Главное меню:",
        reply_markup=await get_main_menu(callback.from_user.id)
    )
    await callback.answer()

@dp.message(F.text == f"{EMOJI_CONTRACT} Заключение договора")
async def contract_handler(message: types.Message):
    logger.info(f"User {message.from_user.id} requested contract")
    await message.answer(
        "Выберите тип договора:",
        reply_markup=await get_contract_type_menu()
    )

@dp.callback_query(F.data == "contract_physical")
async def contract_physical_handler(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"User {callback.from_user.id} selected physical contract")
    await callback.message.edit_text(
        "Вы выбрали договор для физического лица. Давайте заполним данные.",
        reply_markup=None
    )
    await callback.message.answer(
        "Введите ваше ФИО (в именительном падеже):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_full_name)
    await callback.answer()

@dp.message(Form.physical_full_name)
async def process_physical_full_name(message: types.Message, state: FSMContext):
    logger.info(f"Processing full name for user {message.from_user.id}")
    await state.update_data(full_name=sanitize_input(message.text))
    await message.answer(
        "Введите идентификационный номер паспорта:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_passport_id)

@dp.message(Form.physical_passport_id)
async def process_physical_passport_id(message: types.Message, state: FSMContext):
    logger.info(f"Processing passport ID for user {message.from_user.id}")
    await state.update_data(passport_id=sanitize_input(message.text))
    await message.answer(
        "Введите дату выдачи паспорта (ДД.ММ.ГГГГ):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_passport_issue_date)

@dp.message(Form.physical_passport_issue_date)
async def process_physical_passport_issue_date(message: types.Message, state: FSMContext):
    logger.info(f"Processing passport issue date for user {message.from_user.id}")
    try:
        date = validate_passport_date(message.text)
        await state.update_data(passport_issue_date=date)
        await message.answer(
            "Введите кем выдан паспорт:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.physical_passport_issued_by)
    except ValueError as e:
        logger.warning(f"Invalid passport date from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
        return

@dp.message(Form.physical_passport_issued_by)
async def process_physical_passport_issued_by(message: types.Message, state: FSMContext):
    logger.info(f"Processing passport issued by for user {message.from_user.id}")
    await state.update_data(passport_issued_by=sanitize_input(message.text))
    await message.answer(
        "Введите индекс и адрес проживания:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_living_address)

@dp.message(Form.physical_living_address)
async def process_physical_living_address(message: types.Message, state: FSMContext):
    logger.info(f"Processing living address for user {message.from_user.id}")
    await state.update_data(living_address=sanitize_input(message.text))
    
    builder = ReplyKeyboardBuilder()
    builder.button(text="✅ Совпадает")
    builder.button(text="❌ Отменить заполнение")
    builder.adjust(2)
    
    await message.answer(
        "Введите дрес регистрации или нажмите '✅ Совпадает' если совпадает с адресом проживания",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.physical_registration_address)

@dp.message(Form.physical_registration_address)
async def process_physical_registration_address(message: types.Message, state: FSMContext):
    logger.info(f"Processing registration address for user {message.from_user.id}")
    
    if message.text == "✅ Совпадает":
        data = await state.get_data()
        await state.update_data(registration_address=data['living_address'])
    else:
        await state.update_data(registration_address=sanitize_input(message.text))
    
    await message.answer(
        "Введите ваш телефон (+375XXXXXXXXX):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.physical_phone)

@dp.message(Form.physical_phone)
async def process_physical_phone(message: types.Message, state: FSMContext):
    logger.info(f"Processing phone for user {message.from_user.id}")
    try:
        phone = validate_phone(message.text)
        await state.update_data(phone=phone)
        await message.answer(
            "Введите ваш email:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.physical_email)
    except ValueError as e:
        logger.warning(f"Invalid phone from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
        return

@dp.message(Form.physical_email)
async def process_physical_email(message: types.Message, state: FSMContext):
    logger.info(f"Processing email for user {message.from_user.id}")
    try:
        email = validate_email(message.text)
        await state.update_data(email=email)
        
        data = await state.get_data()
        try:
            validated_data = PhysicalPersonData(**data)
            text = (
                "Проверьте введенные данные:\n\n"
                f"ФИО: {validated_data.full_name}\n"
                f"Номер паспорта: {validated_data.passport_id}\n"
                f"Дата выдачи: {validated_data.passport_issue_date}\n"
                f"Кем выдан: {validated_data.passport_issued_by}\n"
                f"Адрес проживания: {validated_data.living_address}\n"
                f"Адрес регистрации: {validated_data.registration_address}\n"
                f"Телефон: {validated_data.phone}\n"
                f"Email: {validated_data.email}\n\n"
                "*в соответствии со Ст. 6. «Обработка персональных данных без согласия "
                "субъекта персональных данных» Закона «О защите персональных данных» "
                "согласие субъекта персональных данных на обработку персональных данных, "
                "при заключении договора на КПГ не требуется.\n\n"
				"Все верно?"
            )
            
            await message.answer(
                text,
                reply_markup=await get_confirm_menu("physical")
            )
            await state.set_state(Form.physical_confirm)
        except ValidationError as e:
            logger.warning(f"Validation error for user {message.from_user.id}: {e}")
            await message.answer(f"Ошибка в данных: {str(e)}")
            return
    except ValueError as e:
        logger.warning(f"Invalid email from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
        return

@dp.callback_query(F.data == "confirm_physical", Form.physical_confirm)
async def confirm_physical_contract(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"User {callback.from_user.id} confirmed physical contract")
    user = callback.from_user
    data = await state.get_data()
    
    try:
        validated_data = PhysicalPersonData(**data)

        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO contracts_physical (user_id, username, full_name, passport_id, passport_issue_date, "
                "passport_issued_by, living_address, registration_address, phone, email) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                user.id,
                user.username,
                validated_data.full_name,
                encrypt_data(validated_data.passport_id),
                validated_data.passport_issue_date,
                validated_data.passport_issued_by,
                validated_data.living_address,
                validated_data.registration_address,
                encrypt_data(validated_data.phone),
                validated_data.email
            )
        
        await callback.message.edit_text(
            "Данные сохранены. Наш менеджер свяжется с вами для завершения оформления договора.",
            reply_markup=None
        )
        await callback.message.answer(
            "Главное меню:",
            reply_markup=await get_main_menu(user.id)
        )
        
        user_mention = await get_user_mention(user)
        admin_text = (
            f"{EMOJI_NEW} Новый договор (физ. лицо) от {user_mention}\n\n"
            f"ФИО: {validated_data.full_name}\n"
            f"Телефон: {validated_data.phone}\n"
            f"Email: {validated_data.email}"
        )
        moderator_text = (
            f"{EMOJI_NEW} Новый договор (физ. лицо) (ID: {user.id})\n\n"
            f"ФИО: {validated_data.full_name}\n"
            f"Телефон: {validated_data.phone}\n"
            f"Email: {validated_data.email}"
        )
        
        await notify_admins(admin_text, EMOJI_CONTRACT, notification_type="contract")
        await notify_moderators(moderator_text, EMOJI_CONTRACT, notification_type="contract")
        
        await state.clear()
        logger.info(f"Physical contract for user {user.id} saved successfully")
    except Exception as e:
        logger.error(f"Failed to save physical contract for user {user.id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer(
            "Произошла ошибка при сохранении данных. Пожалуйста, попробуйте позже."
        )
    finally:
        await callback.answer()

@dp.callback_query(F.data == "cancel_confirm", Form.physical_confirm)
async def cancel_physical_contract(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"User {callback.from_user.id} canceled physical contract confirmation")
    await callback.message.edit_text(
        "Заполнение договора отменено.",
        reply_markup=None
    )
    await callback.message.answer(
        "Главное меню:",
        reply_markup=await get_main_menu(callback.from_user.id)
    )
    await state.clear()
    await callback.answer()

@dp.callback_query(F.data == "contract_legal")
async def contract_legal_handler(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"User {callback.from_user.id} selected legal contract")
    await callback.message.edit_text(
        "Вы выбрали договор для юридического лица. Давайте заполним данные.",
        reply_markup=None
    )
    await callback.message.answer(
        "Введите полное наименование организации:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_organization_name)
    await callback.answer()

@dp.message(Form.legal_organization_name)
async def process_legal_organization_name(message: types.Message, state: FSMContext):
    logger.info(f"Processing organization name for user {message.from_user.id}")
    await state.update_data(organization_name=sanitize_input(message.text))
    await message.answer(
        "Введите индекс и почтовый адрес организации:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_postal_address)

@dp.message(Form.legal_postal_address)
async def process_legal_postal_address(message: types.Message, state: FSMContext):
    logger.info(f"Processing postal address for user {message.from_user.id}")
    await state.update_data(postal_address=sanitize_input(message.text))
    
    builder = ReplyKeyboardBuilder()
    builder.button(text="✅ Совпадает")
    builder.button(text="❌ Отменить заполнение")
    builder.adjust(2)
    
    await message.answer(
        "Введите индес и юридический адрес (если отличается от почтового) или нажмите '✅ Совпадает':",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.legal_legal_address)

@dp.message(Form.legal_legal_address)
async def process_legal_legal_address(message: types.Message, state: FSMContext):
    logger.info(f"Processing legal address for user {message.from_user.id}")
    if message.text == "✅ Совпадает":
        data = await state.get_data()
        await state.update_data(legal_address=data['postal_address'])
    else:
        await state.update_data(legal_address=sanitize_input(message.text))
    
    await message.answer(
        "Введите контактный телефон (+375XXXXXXXXX):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_phone)

@dp.message(Form.legal_phone)
async def process_legal_phone(message: types.Message, state: FSMContext):
    logger.info(f"Processing phone for user {message.from_user.id}")
    try:
        phone = validate_phone(message.text)
        await state.update_data(phone=phone)
        await message.answer(
            "Введите вид деятельности организации:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_activity_type)
    except ValueError as e:
        logger.warning(f"Invalid phone from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
        return

@dp.message(Form.legal_activity_type)
async def process_legal_activity_type(message: types.Message, state: FSMContext):
    logger.info(f"Processing activity type for user {message.from_user.id}")
    await state.update_data(activity_type=sanitize_input(message.text))
    
    # Создаем клавиатуру с кнопками
    builder = ReplyKeyboardBuilder()
    builder.button(text="➡️ Пропустить")
    builder.button(text="❌ Отменить заполнение")
    builder.adjust(2)
    
    await message.answer(
        "Введите ОКПО организации (8 цифр) или нажмите 'Пропустить':",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(Form.legal_okpo)

@dp.message(Form.legal_okpo)
async def process_legal_okpo(message: types.Message, state: FSMContext):
    if message.text == "➡️ Пропустить":
        await state.update_data(okpo=None)
        await message.answer(
            "Введите УНП организации (9 цифр):",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_unp)
        return
    
    try:
        okpo = validate_okpo(message.text) if message.text else None
        await state.update_data(okpo=okpo)
        await message.answer(
            "Введите УНП организации (9 цифр):",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_unp)
    except ValueError as e:
        logger.warning(f"Invalid OKPO from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
		
@dp.message(Form.legal_unp)
async def process_legal_unp(message: types.Message, state: FSMContext):
    logger.info(f"Processing UNP for user {message.from_user.id}")
    try:
        unp = validate_unp(message.text)
        await state.update_data(unp=unp)
        await message.answer(
            "Введите расчетный счет (IBAN BY...):",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_account_number)
    except ValueError as e:
        logger.warning(f"Invalid UNP from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
        return

@dp.message(Form.legal_account_number)
async def process_legal_account_number(message: types.Message, state: FSMContext):
    logger.info(f"Processing account number for user {message.from_user.id}")
    try:
        account = validate_account(message.text)
        await state.update_data(account_number=account)
        await message.answer(
            "Введите название банка:",
            reply_markup=await get_cancel_keyboard()
        )
        await state.set_state(Form.legal_bank_name)
    except ValueError as e:
        logger.warning(f"Invalid account number from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
        return

@dp.message(Form.legal_bank_name)
async def process_legal_bank_name(message: types.Message, state: FSMContext):
    logger.info(f"Processing bank name for user {message.from_user.id}")
    await state.update_data(bank_name=sanitize_input(message.text))
    await message.answer(
        "Введите БИК банка:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_bank_bic)

@dp.message(Form.legal_bank_bic)
async def process_legal_bank_bic(message: types.Message, state: FSMContext):
    logger.info(f"Processing bank BIC for user {message.from_user.id}")
    await state.update_data(bank_bic=sanitize_input(message.text))
    await message.answer(
        "Введите адрес банка:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_bank_address)

@dp.message(Form.legal_bank_address)
async def process_legal_bank_address(message: types.Message, state: FSMContext):
    logger.info(f"Processing bank address for user {message.from_user.id}")
    await state.update_data(bank_address=sanitize_input(message.text))
    await message.answer(
        "Введите ФИО подписанта:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_signatory_name)

@dp.message(Form.legal_signatory_name)
async def process_legal_signatory_name(message: types.Message, state: FSMContext):
    logger.info(f"Processing signatory name for user {message.from_user.id}")
    await state.update_data(signatory_name=sanitize_input(message.text))
    await message.answer(
        "Введите основание полномочий подписанта (Устав, Доверенность и т.д.):",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_authority_basis)

@dp.message(Form.legal_authority_basis)
async def process_legal_authority_basis(message: types.Message, state: FSMContext):
    logger.info(f"Processing authority basis for user {message.from_user.id}")
    await state.update_data(authority_basis=sanitize_input(message.text))
    await message.answer(
        "Введите должность подписанта:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_position)

@dp.message(Form.legal_position)
async def process_legal_position(message: types.Message, state: FSMContext):
    logger.info(f"Processing position for user {message.from_user.id}")
    await state.update_data(position=sanitize_input(message.text))
    await message.answer(
        "Введите email для связи:",
        reply_markup=await get_cancel_keyboard()
    )
    await state.set_state(Form.legal_email)

@dp.message(Form.legal_email)
async def process_legal_email(message: types.Message, state: FSMContext):
    logger.info(f"Processing email for user {message.from_user.id}")
    try:
        email = validate_email(message.text)
        await state.update_data(email=email)
        
        data = await state.get_data()
        try:
            validated_data = LegalPersonData(**data)
            text = (
                "Проверьте введенные данные:\n\n"
                f"Организация: {validated_data.organization_name}\n"
                f"Почтовый адрес: {validated_data.postal_address}\n"
                f"Юридический адрес: {validated_data.legal_address}\n"
                f"Телефон: {validated_data.phone}\n"
                f"Вид деятельности: {validated_data.activity_type}\n"
                f"ОКПО: {validated_data.okpo}\n"
                f"УНП: {validated_data.unp}\n"
                f"Расчетный счет: {validated_data.account_number}\n"
                f"Банк: {validated_data.bank_name}\n"
                f"БИК: {validated_data.bank_bic}\n"
                f"Адрес банка: {validated_data.bank_address}\n"
                f"Подписант: {validated_data.signatory_name}\n"
                f"Основание полномочий: {validated_data.authority_basis}\n"
                f"Должность: {validated_data.position}\n"
                f"Email: {validated_data.email}\n\n"
                "*в соответствии со Ст. 6. «Обработка персональных данных без согласия "
                "субъекта персональных данных» Закона «О защите персональных данных» "
                "согласие субъекта персональных данных на обработку персональных данных, "
                "при заключении договора на КПГ не требуется.\n\n"
				"Все верно?"
            )
            
            await message.answer(
                text,
                reply_markup=await get_confirm_menu("legal")
            )
            await state.set_state(Form.legal_confirm)
        except ValidationError as e:
            logger.warning(f"Validation error for user {message.from_user.id}: {e}")
            await message.answer(f"Ошибка в данных: {str(e)}")
            return
    except ValueError as e:
        logger.warning(f"Invalid email from user {message.from_user.id}: {message.text}")
        await message.answer(str(e))
        return

@dp.callback_query(F.data == "confirm_legal", Form.legal_confirm)
async def confirm_legal_contract(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"User {callback.from_user.id} confirmed legal contract")
    user = callback.from_user
    data = await state.get_data()
    
    try:
        validated_data = LegalPersonData(**data)
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO contracts_legal (user_id, username, organization_name, postal_address, legal_address, "
                "phone, activity_type, okpo, unp, account_number, bank_name, bank_bic, bank_address, "
                "signatory_name, authority_basis, position, email) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
                user.id,
                user.username,
                validated_data.organization_name,
                validated_data.postal_address,
                validated_data.legal_address,
                encrypt_data(validated_data.phone),
                validated_data.activity_type,
                encrypt_data(validated_data.okpo) if validated_data.okpo is not None else None,
                encrypt_data(validated_data.unp),
                encrypt_data(validated_data.account_number),
                validated_data.bank_name,
                validated_data.bank_bic,
                validated_data.bank_address,
                validated_data.signatory_name,
                validated_data.authority_basis,
                validated_data.position,
                validated_data.email
            )
        
        await callback.message.edit_text(
            "Данные сохранены. Наш менеджер свяжется с вами для завершения оформления договора.",
            reply_markup=None
        )
        await callback.message.answer(
            "Главное меню:",
            reply_markup=await get_main_menu(user.id)
        )
        
        user_mention = await get_user_mention(user)
        admin_text = (
            f"{EMOJI_NEW} Новый договор (юр. лицо) от {user_mention}\n\n"
            f"Организация: {validated_data.organization_name}\n"
            f"Телефон: {validated_data.phone}\n"
            f"Email: {validated_data.email}"
        )
        moderator_text = (
            f"{EMOJI_NEW} Новый договор (юр. лицо) (ID: {user.id})\n\n"
            f"Организация: {validated_data.organization_name}\n"
            f"Телефон: {validated_data.phone}\n"
            f"Email: {validated_data.email}"
        )
        
        await notify_admins(admin_text, EMOJI_CONTRACT, notification_type="contract")
        await notify_moderators(moderator_text, EMOJI_CONTRACT, notification_type="contract")
        
        await state.clear()
        logger.info(f"Legal contract for user {user.id} saved successfully")
    except Exception as e:
        logger.error(f"Failed to save legal contract for user {user.id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer(
            "Произошла ошибка при сохранении данных. Пожалуйста, попробуйте позже."
        )
    finally:
        await callback.answer()

@dp.callback_query(F.data == "cancel_confirm", Form.legal_confirm)
async def cancel_legal_contract(callback: types.CallbackQuery, state: FSMContext):
    logger.info(f"User {callback.from_user.id} canceled legal contract confirmation")
    await callback.message.edit_text(
        "Заполнение договора отменено.",
        reply_markup=None
    )
    await callback.message.answer(
        "Главное меню:",
        reply_markup=await get_main_menu(callback.from_user.id)
    )
    await state.clear()
    await callback.answer()

# Moderator handlers
@dp.message(F.text == "🔧 Модераторское меню")
async def moderator_menu_handler(message: types.Message):
    logger.info(f"User {message.from_user.id} accessed moderator menu")
    if not await is_moderator(message.from_user.id):
        logger.warning(f"User {message.from_user.id} is not a moderator")
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    await message.answer(
        "Модераторское меню:",
        reply_markup=await get_moderator_menu()
    )

@dp.message(F.text == "📋 Неотвеченные вопросы")
async def unanswered_questions_handler(message: types.Message):
    logger.info(f"User {message.from_user.id} requested unanswered questions")
    
    if not await is_moderator(message.from_user.id):
        logger.warning(f"User {message.from_user.id} is not a moderator")
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Get first unanswered question
            questions = await conn.fetch(
                "SELECT id, user_id, username, question FROM questions "
                "WHERE answer IS NULL AND skipped_at IS NULL "
                "ORDER BY created_at LIMIT 1"
            )
            
            if not questions:
                await message.answer("Нет неотвеченных вопросов.", reply_markup=await get_moderator_menu())
                return
                
            question = questions[0]
            
            # Check if there are more questions
            has_next = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL)",
                question['id']
            )
            
            question_text = (
                f"Вопрос от пользователя {question['username'] or question['user_id']}:\n\n"
                f"{question['question']}"
            )
            
            await message.answer(
                question_text,
                reply_markup=await get_question_action_menu(question['id'], has_next, False)
            )
    except Exception as e:
        logger.error(f"Failed to get unanswered questions: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при получении вопросов.")

@dp.callback_query(F.data.startswith("prev_question_"))
async def prev_question_handler(callback: types.CallbackQuery):
    question_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Get previous question
            question = await conn.fetchrow(
                "SELECT id, user_id, username, question FROM questions "
                "WHERE id < $1 AND answer IS NULL AND skipped_at IS NULL "
                "ORDER BY id DESC LIMIT 1",
                question_id
            )
            
            if not question:
                await callback.answer("Это первый вопрос в списке.")
                return
                
            # Check navigation availability
            has_prev = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id < $1 AND answer IS NULL AND skipped_at IS NULL)",
                question['id']
            )
            has_next = True  # Since we came from a next question
            
            question_text = (
                f"Вопрос от пользователя {question['username'] or question['user_id']}:\n\n"
                f"{question['question']}"
            )
            
            await callback.message.edit_text(
                question_text,
                reply_markup=await get_question_action_menu(question['id'], has_next, has_prev)
            )
    except Exception as e:
        logger.error(f"Failed to get previous question: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.answer("Произошла ошибка при загрузке вопроса.")
    finally:
        await callback.answer()

@dp.callback_query(F.data.startswith("next_question_"))
async def next_question_handler(callback: types.CallbackQuery):
    question_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Get next question
            question = await conn.fetchrow(
                "SELECT id, user_id, username, question FROM questions "
                "WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL "
                "ORDER BY id LIMIT 1",
                question_id
            )
            
            if not question:
                await callback.answer("Это последний вопрос в списке.")
                return
                
            # Check navigation availability
            has_next = await conn.fetchval(
                "SELECT EXISTS(SELECT 1 FROM questions WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL)",
                question['id']
            )
            has_prev = True  # Since we came from a previous question
            
            question_text = (
                f"Вопрос от пользователя {question['username'] or question['user_id']}:\n\n"
                f"{question['question']}"
            )
            
            await callback.message.edit_text(
                question_text,
                reply_markup=await get_question_action_menu(question['id'], has_next, has_prev)
            )
    except Exception as e:
        logger.error(f"Failed to get next question: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.answer("Произошла ошибка при загрузке вопроса.")
    finally:
        await callback.answer()

@dp.callback_query(F.data.startswith("answer_"))
async def answer_question_handler(callback: types.CallbackQuery, state: FSMContext):
    question_id = int(callback.data.split("_")[1])
    await state.update_data(question_id=question_id)
    
    # Сохраняем информацию о предыдущем/следующем вопросе из callback
    parts = callback.data.split("_")
    if len(parts) > 2:
        await state.update_data(
            prev_question=parts[2] if "prev" in parts else None,
            next_question=parts[2] if "next" in parts else None
        )
    
    await callback.message.edit_text(
        "Введите ответ на вопрос:",
        reply_markup=None
    )
    await callback.message.answer(
        "Отправьте текст ответа:",
        reply_markup=await get_cancel_reply_keyboard()
    )
    await state.set_state(Form.waiting_for_answer)
    await callback.answer()

@dp.callback_query(F.data.startswith("skip_"))
async def skip_question_handler(callback: types.CallbackQuery):
    parts = callback.data.split("_")
    question_id = int(parts[1])
    moderator = callback.from_user
    
    # Проверяем, есть ли информация о следующем вопросе
    next_question_id = None
    if len(parts) > 2 and parts[2].isdigit():
        next_question_id = int(parts[2])
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE questions SET skipped_at = CURRENT_TIMESTAMP WHERE id = $1",
                question_id
            )
            
            # Если есть следующий вопрос, загружаем его
            if next_question_id:
                next_question = await conn.fetchrow(
                    "SELECT id, user_id, username, question FROM questions WHERE id = $1",
                    next_question_id
                )
                
                if next_question:
                    # Проверяем навигацию для нового вопроса
                    has_next = await conn.fetchval(
                        "SELECT EXISTS(SELECT 1 FROM questions WHERE id > $1 AND answer IS NULL AND skipped_at IS NULL)",
                        next_question['id']
                    )
                    has_prev = await conn.fetchval(
                        "SELECT EXISTS(SELECT 1 FROM questions WHERE id < $1 AND answer IS NULL AND skipped_at IS NULL)",
                        next_question['id']
                    )
                    
                    question_text = (
                        f"Вопрос от пользователя {next_question['username'] or next_question['user_id']}:\n\n"
                        f"{next_question['question']}"
                    )
                    
                    await callback.message.edit_text(
                        question_text,
                        reply_markup=await get_question_action_menu(next_question['id'], has_next, has_prev)
                    )
                    await callback.answer("Вопрос пропущен. Загружен следующий вопрос.")
                    return
            
            await callback.message.edit_text(
                "Вопрос пропущен.",
                reply_markup=None
            )
            
            # Notify other moderators
            moderator_mention = await get_user_mention(moderator)
            notify_text = f"Вопрос ID {question_id} был пропущен модератором {moderator_mention}"
            await notify_moderators(notify_text, EMOJI_WARNING)
            
    except Exception as e:
        logger.error(f"Failed to skip question {question_id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Произошла ошибка при пропуске вопроса.")
    finally:
        await callback.answer()

@dp.message(Form.waiting_for_answer, F.text == "❌ Отменить ответ")
async def cancel_answer_handler(message: types.Message, state: FSMContext):
    logger.info(f"Moderator {message.from_user.id} canceled answering")
    await message.answer(
        "Ответ отменен.",
        reply_markup=await get_moderator_menu()
    )
    await state.clear()

@dp.message(Form.waiting_for_answer)
async def process_answer(message: types.Message, state: FSMContext):
    answer = sanitize_input(message.text)
    data = await state.get_data()
    question_id = data['question_id']
    moderator = message.from_user
    
    logger.info(f"Processing answer for question {question_id} by moderator {moderator.id}")
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Get question info
            question = await conn.fetchrow(
                "SELECT user_id, question FROM questions WHERE id = $1",
                question_id
            )
            
            if not question:
                await message.answer("Вопрос не найден.", reply_markup=await get_moderator_menu())
                await state.clear()
                return
                
            # Save answer
            await conn.execute(
                "UPDATE questions SET answer = $1, answered_by = $2, answered_at = CURRENT_TIMESTAMP WHERE id = $3",
                answer,
                moderator.username or moderator.full_name,
                question_id
            )
            
            # Notify user
            try:
                await bot.send_message(
                    question['user_id'],
                    f"Ответ на ваш вопрос:\n\n{question['question']}\n\n{answer}"
                )
            except Exception as e:
                logger.warning(f"Failed to notify user {question['user_id']} about answer: {e}")
                
            await message.answer(
                "Ответ сохранен и отправлен пользователю.",
                reply_markup=await get_moderator_menu()
            )
            
            # Notify other moderators
            moderator_mention = await get_user_mention(moderator)
            notify_text = f"Вопрос ID {question_id} был отвечен модератором {moderator_mention}"
            await notify_admins(notify_text, EMOJI_DONE)
            
    except Exception as e:
        logger.error(f"Failed to process answer for question {question_id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при сохранении ответа.")
    finally:
        await state.clear()

@dp.callback_query(F.data.startswith("skip_"))
async def skip_question_handler(callback: types.CallbackQuery):
    question_id = int(callback.data.split("_")[1])
    moderator = callback.from_user
    
    logger.info(f"Moderator {moderator.id} skipping question {question_id}")
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE questions SET skipped_at = CURRENT_TIMESTAMP WHERE id = $1",
                question_id
            )
            
            await callback.message.edit_text(
                "Вопрос пропущен. Он снова появится в списке неотвеченных.",
                reply_markup=None
            )
            
            # Notify other moderators
            moderator_mention = await get_user_mention(moderator)
            notify_text = f"Вопрос ID {question_id} был пропущен модератором {moderator_mention}"
            await notify_moderators(notify_text, EMOJI_WARNING)
            
    except Exception as e:
        logger.error(f"Failed to skip question {question_id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Произошла ошибка при пропуске вопроса.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "cancel_question")
async def cancel_question_action_handler(callback: types.CallbackQuery):
    logger.info(f"Moderator {callback.from_user.id} canceled question action")
    await callback.message.edit_text(
        "Действие отменено.",
        reply_markup=None
    )
    await callback.message.answer(
        "Модераторское меню:",
        reply_markup=await get_moderator_menu()
    )
    await callback.answer()

@dp.message(F.text == "📝 Просмотреть договоры")
async def view_contracts_handler(message: types.Message):

    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Check physical contracts
            physical_count = await conn.fetchval(
                "SELECT COUNT(*) FROM contracts_physical WHERE status = 'pending'"
            )
            
            # Check legal contracts
            legal_count = await conn.fetchval(
                "SELECT COUNT(*) FROM contracts_legal WHERE status = 'pending'"
            )
            
            if physical_count == 0 and legal_count == 0:
                await message.answer("Нет договоров для обработки.", reply_markup=await get_moderator_menu())
                return
                
            text = "Выберите тип договоров для обработки:\n\n"
            if physical_count > 0:
                text += f"📋 Физические лица: {physical_count} на обработку\n"
            if legal_count > 0:
                text += f"📋 Юридические лица: {legal_count} на обработку"
            
            builder = InlineKeyboardBuilder()
            if physical_count > 0:
                builder.button(text="Физические лица", callback_data="view_physical")
            if legal_count > 0:
                builder.button(text="Юридические лица", callback_data="view_legal")
            builder.button(text="⬅️ Назад", callback_data="moderator_back")
            builder.adjust(2, 1)
            
            await message.answer(
                text,
                reply_markup=builder.as_markup()
            )
            
    except Exception as e:
        logger.error(f"Failed to get contracts count: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при получении списка договоров.")

@dp.callback_query(F.data == "view_physical")
async def view_physical_contracts_handler(callback: types.CallbackQuery):
    logger.info(f"Moderator {callback.from_user.id} viewing physical contracts")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            contract = await conn.fetchrow(
                "SELECT * FROM contracts_physical WHERE status = 'pending' ORDER BY created_at LIMIT 1"
            )
            
            if not contract:
                await callback.message.edit_text(
                    "Нет договоров физ. лиц для обработки.",
                    reply_markup=None
                )
                await callback.message.answer(
                    "Модераторское меню:",
                    reply_markup=await get_moderator_menu()
                )
                return
            
            # Check if there are more contracts
            has_more = await conn.fetchval(
                "SELECT COUNT(*) > 1 FROM contracts_physical WHERE status = 'pending'"
            )
            
            await display_contract(callback, contract, "physical", has_more)
            
    except Exception as e:
        logger.error(f"Failed to view physical contract: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Произошла ошибка при просмотре договора.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "view_legal")
async def view_legal_contracts_handler(callback: types.CallbackQuery):
    logger.info(f"Moderator {callback.from_user.id} viewing legal contracts")
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            contract = await conn.fetchrow(
                "SELECT * FROM contracts_legal WHERE status = 'pending' ORDER BY created_at LIMIT 1"
            )
            
            if not contract:
                await callback.message.edit_text(
                    "Нет договоров юр. лиц для обработки.",
                    reply_markup=None
                )
                await callback.message.answer(
                    "Модераторское меню:",
                    reply_markup=await get_moderator_menu()
                )
                return
            
            # Check if there are more contracts
            has_more = await conn.fetchval(
                "SELECT COUNT(*) > 1 FROM contracts_legal WHERE status = 'pending'"
            )
            
            await display_contract(callback, contract, "legal", has_more)
            
    except Exception as e:
        logger.error(f"Failed to view legal contract: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Произошла ошибка при просмотре договора.")
    finally:
        await callback.answer()

@dp.callback_query(F.data.startswith("process_contract_"))
async def process_contract_handler(callback: types.CallbackQuery):
    parts = callback.data.split("_")
    contract_type = parts[2]
    contract_id = int(parts[3])
    moderator = callback.from_user
    
    logger.info(f"Moderator {moderator.id} processing {contract_type} contract {contract_id}")
    
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            if contract_type == "physical":
                await conn.execute(
                    "UPDATE contracts_physical SET status = 'processed' WHERE id = $1",
                    contract_id
                )
                contract = await conn.fetchrow(
                    "SELECT user_id FROM contracts_physical WHERE id = $1",
                    contract_id
                )
            else:
                await conn.execute(
                    "UPDATE contracts_legal SET status = 'processed' WHERE id = $1",
                    contract_id
                )
                contract = await conn.fetchrow(
                    "SELECT user_id FROM contracts_legal WHERE id = $1",
                    contract_id
                )
            
            # Notify user
            try:
                await bot.send_message(
                    contract['user_id'],
                    "Ваш договор обработан. Наш менеджер свяжется с вами в ближайшее время."
                )
            except Exception as e:
                logger.warning(f"Failed to notify user {contract['user_id']} about contract processing: {e}")
                
            await callback.message.edit_text(
                "Договор обработан. Пользователь уведомлен.",
                reply_markup=None
            )
            
            # Notify other moderators
            moderator_mention = await get_user_mention(moderator)
            notify_text = f"Договор {contract_type} ID {contract_id} обработан модератором {moderator_mention}"
            await notify_admins(notify_text, EMOJI_DONE)
            
    except Exception as e:
        logger.error(f"Failed to process {contract_type} contract {contract_id}: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Произошла ошибка при обработке договора.")
    finally:
        await callback.answer()

@dp.callback_query(F.data.startswith("hide_contract_"))
async def hide_contract_handler(callback: types.CallbackQuery):
    parts = callback.data.split("_")
    contract_type = parts[2]
    contract_id = int(parts[3])
    moderator = callback.from_user
    
    logger.info(f"Moderator {moderator.id} hiding {contract_type} contract {contract_id}")
    
    await callback.message.edit_text(
        "Договор временно скрыт. Он снова появится при следующем просмотре.",
        reply_markup=None
    )
    
    # No database update - just hide from view
    await callback.answer()
    
    # Show next contract if available
    await show_next_contract(callback, contract_type, contract_id)

async def show_next_contract(callback: types.CallbackQuery, contract_type: str, current_id: int):
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Get next contract
            if contract_type == "physical":
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_physical WHERE id > $1 AND status = 'pending' ORDER BY id LIMIT 1",
                    current_id
                )
            else:
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_legal WHERE id > $1 AND status = 'pending' ORDER BY id LIMIT 1",
                    current_id
                )
            
            if contract:
                await display_contract(callback, contract, contract_type, True)
            else:
                await callback.message.answer("Это последний договор в списке.")
    except Exception as e:
        logger.error(f"Failed to show next contract: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)

async def show_prev_contract(callback: types.CallbackQuery, contract_type: str, current_id: int):
    pool = await get_db_connection()
    try:
        async with pool.acquire() as conn:
            # Get previous contract
            if contract_type == "physical":
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_physical WHERE id < $1 AND status = 'pending' ORDER BY id DESC LIMIT 1",
                    current_id
                )
            else:
                contract = await conn.fetchrow(
                    "SELECT * FROM contracts_legal WHERE id < $1 AND status = 'pending' ORDER BY id DESC LIMIT 1",
                    current_id
                )
            
            if contract:
                await display_contract(callback, contract, contract_type, True)
            else:
                await callback.message.answer("Это первый договор в списке.")
    except Exception as e:
        logger.error(f"Failed to show previous contract: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)

@dp.callback_query(F.data.startswith("next_contract_"))
async def next_contract_handler(callback: types.CallbackQuery):
    parts = callback.data.split("_")
    contract_type = parts[2]
    contract_id = int(parts[3])
    await show_next_contract(callback, contract_type, contract_id)
    await callback.answer()

@dp.callback_query(F.data.startswith("prev_contract_"))
async def prev_contract_handler(callback: types.CallbackQuery):
    parts = callback.data.split("_")
    contract_type = parts[2]
    contract_id = int(parts[3])
    await show_prev_contract(callback, contract_type, contract_id)
    await callback.answer()

@dp.callback_query(F.data == "moderator_back")
async def moderator_back_handler(callback: types.CallbackQuery):
    logger.info(f"Moderator {callback.from_user.id} returning to moderator menu")
    await callback.message.edit_text(
        "Возвращаемся в модераторское меню",
        reply_markup=None
    )
    await callback.message.answer(
        "Модераторское меню:",
        reply_markup=await get_moderator_menu()
    )
    await callback.answer()

# Обработчик создания отложенного сообщения
@dp.message(F.text == "⏱ Создать отложенное сообщение")
async def create_delayed_message(message: types.Message, state: FSMContext):

    
    builder = ReplyKeyboardBuilder()
    builder.button(text="📝 Только текст")
    builder.button(text="🖼 Только фото")
    builder.button(text="📝+🖼 Текст с фото")
    builder.button(text="❌ Отменить")
    builder.adjust(2, 1, 1)
    
    await message.answer(
        "Выберите тип сообщения:",
        reply_markup=builder.as_markup(resize_keyboard=True)
    )
    await state.set_state(DelayedMessageStates.waiting_for_content)

# Обработчик отмены
@dp.message(StateFilter(DelayedMessageStates), F.text == "❌ Отменить")
async def cancel_delayed_message(message: types.Message, state: FSMContext):
    await state.clear()
    await message.answer(
        "Создание отложенного сообщения отменено.",
        reply_markup=await get_moderator_menu()
    )

# Исправленный обработчик для текстовых сообщений:
@dp.message(DelayedMessageStates.waiting_for_text, F.text != "❌ Отменить")
async def process_text_content(message: types.Message, state: FSMContext):
    await state.update_data(text_content=message.text)
    await message.answer(
        "Введите время отправки в формате ДД.ММ.ГГГГ ЧЧ:ММ:",
        reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
    )
    await state.set_state(DelayedMessageStates.waiting_for_time)

# Обработчик выбора типа контента
@dp.message(DelayedMessageStates.waiting_for_content)
async def process_content_type(message: types.Message, state: FSMContext):
    if message.text == "📝 Только текст":
        await state.update_data(content_type="text")
        await message.answer(
            "Введите текст сообщения:",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
        )
        await state.set_state(DelayedMessageStates.waiting_for_text)
    elif message.text in ["🖼 Только фото", "📝+🖼 Текст с фото"]:
        content_type = "photo" if message.text == "🖼 Только фото" else "photo_with_text"
        await state.update_data(content_type=content_type)
        await message.answer(
            "Отправьте фото:",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
        )
        # Устанавливаем состояние ожидания фото
        await state.set_state(DelayedMessageStates.waiting_for_photo)

# Обработчик фото
@dp.message(DelayedMessageStates.waiting_for_photo, F.photo)
async def process_photo(message: types.Message, state: FSMContext):
    data = await state.get_data()
    
    # Сохраняем фото во временную папку
    os.makedirs("temp/delayed_photos", exist_ok=True)
    photo_path = f"temp/delayed_photos/{message.photo[-1].file_id}.jpg"
    
    try:
        # Используем bot.download для загрузки фото
        file_info = await bot.get_file(message.photo[-1].file_id)
        await bot.download_file(file_info.file_path, destination=photo_path)
        
        await state.update_data(photo_path=photo_path)
        
        if data['content_type'] == 'photo_with_text':
            await message.answer(
                "Теперь введите текст сообщения:",
                reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
            )
            await state.set_state(DelayedMessageStates.waiting_for_text)
        else:
            await message.answer(
                "Введите время отправки в формате ДД.ММ.ГГГГ ЧЧ:ММ:",
                reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
            )
            await state.set_state(DelayedMessageStates.waiting_for_time)
            
    except Exception as e:
        logger.error(f"Failed to download photo: {e}", exc_info=True)
        await message.answer("Не удалось сохранить фото. Попробуйте еще раз.")
		
@dp.message(DelayedMessageStates.waiting_for_photo)
async def process_not_photo(message: types.Message):
    await message.answer("Пожалуйста, отправьте фото или отмените действие.")
		
# Обработчик текста
# Исправленный обработчик для времени:
@dp.message(DelayedMessageStates.waiting_for_time, F.text != "❌ Отменить")
async def process_time(message: types.Message, state: FSMContext):
    try:
        send_time = datetime.strptime(message.text, "%d.%m.%Y %H:%M")
        if send_time < datetime.now():
            raise ValueError("Время должно быть в будущем")
        
        await state.update_data(send_time=send_time.isoformat())
        
        builder = ReplyKeyboardBuilder()
        builder.button(text="👥 Всем пользователям")
        builder.button(text="🛡 Только модераторам")
        builder.button(text="👤 Конкретному пользователю")
        builder.button(text="❌ Отменить")
        builder.adjust(2, 1, 1)
        
        await message.answer(
            "Выберите получателей:",
            reply_markup=builder.as_markup(resize_keyboard=True)
        )
        await state.set_state(DelayedMessageStates.waiting_for_recipients)
    except ValueError as e:
        await message.answer(f"Неверный формат времени или время в прошлом. Пожалуйста, введите время в формате ДД.ММ.ГГГГ ЧЧ:ММ")

# Обработчик выбора получателей
@dp.message(DelayedMessageStates.waiting_for_recipients, F.text != "❌ Отменить")
async def process_recipients(message: types.Message, state: FSMContext):
    if message.text == "👤 Конкретному пользователю":
        await message.answer(
            "Введите ID пользователя:",
            reply_markup=ReplyKeyboardBuilder().button(text="❌ Отменить").as_markup(resize_keyboard=True)
        )
        await state.set_state(DelayedMessageStates.waiting_for_user_id)
    else:
        recipient_type = "all" if message.text == "👥 Всем пользователям" else "moderators"
        await state.update_data(recipient_type=recipient_type, recipient_id=None)
        await confirm_and_save_message(message, state)

# Обработчик ID пользователя
@dp.message(DelayedMessageStates.waiting_for_user_id, F.text != "❌ Отменить")
async def process_user_id(message: types.Message, state: FSMContext):
    try:
        user_id = int(message.text)
        await state.update_data(recipient_type="specific", recipient_id=user_id)
        await confirm_and_save_message(message, state)
    except ValueError:
        await message.answer("Неверный ID пользователя. Пожалуйста, введите числовой ID.")

async def confirm_and_save_message(message: types.Message, state: FSMContext):
    data = await state.get_data()
	
	# Конвертируем строку ISO формата обратно в datetime
    send_time = datetime.fromisoformat(data['send_time'])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_id = await conn.fetchval(
            """
            INSERT INTO delayed_messages (
                content_type, text_content, photo_path, send_time, status, 
                recipient_type, recipient_id, created_by
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
            """,
            data['content_type'],
            data.get('text_content'),
            data.get('photo_path'),
            send_time,
            'pending',
            data['recipient_type'],
            data.get('recipient_id'),
            message.from_user.id
        )
    
    # Формируем текст уведомления
    notify_text = f"📨 Новое отложенное сообщение (ID: {message_id})\n\n"
    
    if data.get('text_content'):
        notify_text += f"📝 Текст: {data['text_content']}\n\n"
    
    notify_text += (
        f"⏰ Время отправки: {datetime.fromisoformat(data['send_time']).strftime('%d.%m.%Y %H:%M')}\n"
        f"👥 Получатели: "
    )
    
    if data['recipient_type'] == 'all':
        notify_text += "все пользователи"
    elif data['recipient_type'] == 'moderators':
        notify_text += "модераторы"
    else:
        notify_text += f"пользователь с ID {data['recipient_id']}"
    
    # Создаем клавиатуру с кнопками
    builder = InlineKeyboardBuilder()
    builder.button(text="✅ Одобрить", callback_data=f"approve_msg_{message_id}")
    builder.button(text="❌ Отклонить", callback_data=f"reject_msg_{message_id}")
    builder.button(text="👁️ Скрыть", callback_data=f"hide_msg_{message_id}")
    builder.adjust(2,1)
    
    try:
        # Отправляем уведомление админу
        if data.get('photo_path') and os.path.exists(data['photo_path']):
            with open(data['photo_path'], 'rb') as photo:
                photo_bytes = photo.read()
            input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
            
            if data.get('text_content'):
                await bot.send_photo(
                    config.ADMIN_ID,
                    input_file,
                    caption=notify_text,
                    reply_markup=builder.as_markup()
                )
            else:
                await bot.send_photo(
                    config.ADMIN_ID,
                    input_file,
                    caption=notify_text,
                    reply_markup=builder.as_markup()
                )
        else:
            await bot.send_message(
                config.ADMIN_ID,
                notify_text,
                reply_markup=builder.as_markup()
            )
    except Exception as e:
        logger.error(f"Failed to send notification to admin: {e}", exc_info=True)
    
    await message.answer(
        "Сообщение создано и отправлено на подтверждение администратору.",
        reply_markup=await get_moderator_menu()
    )
    await state.clear()

# Admin handlers
@dp.message(F.text == "👑 Админ-панель")
async def admin_menu_handler(message: types.Message):
    logger.info(f"User {message.from_user.id} accessed admin menu")
    if not await is_admin(message.from_user.id):
        logger.warning(f"User {message.from_user.id} is not an admin")
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    await message.answer(
        "Админ-панель:",
        reply_markup=await get_admin_menu()
    )

@dp.message(F.text == "📊 Статистика")
async def admin_stats_handler(message: types.Message):
    logger.info(f"Admin {message.from_user.id} requested stats")
    if not await is_admin(message.from_user.id):
        logger.warning(f"User {message.from_user.id} is not an admin")
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    try:
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            stats = {
                "users": await conn.fetchval("SELECT COUNT(*) FROM users"),
                "active_users": await conn.fetchval("SELECT COUNT(*) FROM users WHERE last_activity > CURRENT_DATE - INTERVAL '7 days'"),
                "questions": await conn.fetchval("SELECT COUNT(*) FROM questions"),
                "answered_questions": await conn.fetchval("SELECT COUNT(*) FROM questions WHERE answer IS NOT NULL"),
                "pending_questions": await conn.fetchval("SELECT COUNT(*) FROM questions WHERE answer IS NULL AND skipped_at IS NULL"),
                "physical_contracts": await conn.fetchval("SELECT COUNT(*) FROM contracts_physical"),
                "pending_physical": await conn.fetchval("SELECT COUNT(*) FROM contracts_physical WHERE status = 'pending'"),
                "legal_contracts": await conn.fetchval("SELECT COUNT(*) FROM contracts_legal"),
                "pending_legal": await conn.fetchval("SELECT COUNT(*) FROM contracts_legal WHERE status = 'pending'"),
            }
            
            text = (
                "📊 Статистика бота:\n\n"
                f"👥 Пользователи: {stats['users']} (активных за неделю: {stats['active_users']})\n"
                f"❓ Вопросы: {stats['questions']} (отвечено: {stats['answered_questions']}, на рассмотрении: {stats['pending_questions']})\n"
                f"📝 Договоры физ. лиц: {stats['physical_contracts']} (на рассмотрении: {stats['pending_physical']})\n"
                f"📝 Договоры юр. лиц: {stats['legal_contracts']} (на рассмотрении: {stats['pending_legal']})"
            )
            
            await message.answer(text, reply_markup=await get_admin_menu())
            
    except Exception as e:
        logger.error(f"Failed to get stats: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при получении статистики.")

@dp.message(F.text == "📁 Экспорт данных")
async def admin_export_handler(message: types.Message):
    logger.info(f"Admin {message.from_user.id} requested data export")
    if not await is_admin(message.from_user.id):
        logger.warning(f"User {message.from_user.id} is not an admin")
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    builder = InlineKeyboardBuilder()
    builder.button(text="📋 Вопросы", callback_data="export_questions")
    builder.button(text="👤 Физ. лица", callback_data="export_physical")
    builder.button(text="🏢 Юр. лица", callback_data="export_legal")
    builder.button(text="⬅️ Назад", callback_data="admin_back")
    builder.adjust(1, 2, 1)
    
    await message.answer(
        "Выберите данные для экспорта:",
        reply_markup=builder.as_markup()
    )

@dp.callback_query(F.data == "export_questions")
async def export_questions_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} exporting questions")
    await callback.message.edit_text(
        "Подготовка файла с вопросами...",
        reply_markup=None
    )
    
    csv_path = await export_questions_to_csv()
    if not csv_path:
        await callback.message.answer("Не удалось экспортировать вопросы.")
        return
    
    try:
        await callback.message.answer_document(
            BufferedInputFile.from_file(csv_path, filename="questions.csv"),
            caption="Экспорт вопросов завершен."
        )
    except Exception as e:
        logger.error(f"Failed to send questions export: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось отправить файл с вопросами.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "export_physical")
async def export_physical_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} exporting physical contracts")
    await callback.message.edit_text(
        "Подготовка файла с договорами физ. лиц...",
        reply_markup=None
    )
    
    csv_path = await export_physical_contracts_to_csv()
    if not csv_path:
        await callback.message.answer("Не удалось экспортировать договоры физ. лиц.")
        return
    
    try:
        await callback.message.answer_document(
            BufferedInputFile.from_file(csv_path, filename="physical_contracts.csv"),
            caption="Экспорт договоров физ. лиц завершен."
        )
    except Exception as e:
        logger.error(f"Failed to send physical contracts export: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось отправить файл с договорами физ. лиц.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "export_legal")
async def export_legal_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} exporting legal contracts")
    await callback.message.edit_text(
        "Подготовка файла с договорами юр. лиц...",
        reply_markup=None
    )
    
    csv_path = await export_legal_contracts_to_csv()
    if not csv_path:
        await callback.message.answer("Не удалось экспортировать договоры юр. лиц.")
        return
    
    try:
        await callback.message.answer_document(
            BufferedInputFile.from_file(csv_path, filename="legal_contracts.csv"),
            caption="Экспорт договоров юр. лиц завершен."
        )
    except Exception as e:
        logger.error(f"Failed to send legal contracts export: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось отправить файл с договорами юр. лиц.")
    finally:
        await callback.answer()

@dp.message(F.text == "🗃 Управление хранилищем")
async def admin_storage_handler(message: types.Message):
    logger.info(f"Admin {message.from_user.id} requested storage management")
    if not await is_admin(message.from_user.id):
        logger.warning(f"User {message.from_user.id} is not an admin")
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    try:
        disk_usage = shutil.disk_usage("/")
        total_gb = disk_usage.total / (1024 ** 3)
        used_gb = disk_usage.used / (1024 ** 3)
        free_gb = disk_usage.free / (1024 ** 3)
        
        # Check log files size
        log_size = 0
        if os.path.exists("bot.log"):
            log_size = os.path.getsize("bot.log") / (1024 ** 2)  # MB
            
        # Check temp files
        temp_files = 0
        temp_size = 0
        if os.path.exists("temp"):
            for f in os.listdir("temp"):
                fp = os.path.join("temp", f)
                if os.path.isfile(fp):
                    temp_files += 1
                    temp_size += os.path.getsize(fp)
        temp_size_mb = temp_size / (1024 ** 2)
        
        # Check backups
        backup_files = 0
        backup_size = 0
        if os.path.exists("backups"):
            for f in os.listdir("backups"):
                fp = os.path.join("backups", f)
                if os.path.isfile(fp):
                    backup_files += 1
                    backup_size += os.path.getsize(fp)
        backup_size_mb = backup_size / (1024 ** 2)
        
        text = (
            "🗃 Состояние хранилища:\n\n"
            f"💽 Дисковое пространство:\n"
            f"Всего: {total_gb:.2f} GB\n"
            f"Использовано: {used_gb:.2f} GB\n"
            f"Свободно: {free_gb:.2f} GB\n\n"
            f"📄 Файлы:\n"
            f"Лог-файл: {log_size:.2f} MB\n"
            f"Временные файлы: {temp_files} файлов ({temp_size_mb:.2f} MB)\n"
            f"Бэкапы: {backup_files} файлов ({backup_size_mb:.2f} MB)"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="🧹 Очистить временные файлы", callback_data="clean_temp")
        builder.button(text="🗑 Очистить старые бэкапы", callback_data="clean_backups")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(1, 1, 1)
        
        await message.answer(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to get storage info: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при получении информации о хранилище.")

@dp.callback_query(F.data == "clean_temp")
async def clean_temp_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} cleaning temp files")
    try:
        cleaned = await cleanup_temp_files()
        await callback.message.edit_text(
            "Временные файлы очищены.",
            reply_markup=None
        )
    except Exception as e:
        logger.error(f"Failed to clean temp files: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось очистить временные файлы.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "clean_backups")
async def clean_backups_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} cleaning old backups")
    try:
        if os.path.exists("backups"):
            backups = sorted(os.listdir("backups"), key=lambda f: os.path.getmtime(os.path.join("backups", f)))
            # Keep last 5 backups
            for f in backups[:-5]:
                os.remove(os.path.join("backups", f))
                
        await callback.message.edit_text(
            "Старые бэкапы удалены (сохранены 5 последних).",
            reply_markup=None
        )
    except Exception as e:
        logger.error(f"Failed to clean backups: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось очистить бэкапы.")
    finally:
        await callback.answer()

@dp.message(F.text == "🔔 Управление уведомлениями")
async def admin_notifications_handler(message: types.Message):
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    await update_notifications_message(message)

async def update_notifications_message(message: types.Message):
    # Получаем текущие настройки
    admin_questions = await is_notification_enabled('notify_admin_questions')
    admin_contracts = await is_notification_enabled('notify_admin_contracts')
    admin_errors = await is_notification_enabled('notify_admin_errors')
    mod_questions = await is_notification_enabled('notify_moderators_questions')
    mod_contracts = await is_notification_enabled('notify_moderators_contracts')
    
    text = (
        "🔔 Настройки уведомлений:\n\n"
        "📌 Для администратора:\n"
        f"1. Новые вопросы: {'вкл' if admin_questions else 'выкл'}\n"
        f"2. Новые договоры: {'вкл' if admin_contracts else 'выкл'}\n"
        f"3. Ошибки системы: {'вкл' if admin_errors else 'выкл'}\n\n"
        "📌 Для модераторов:\n"
        f"4. Новые вопросы: {'вкл' if mod_questions else 'выкл'}\n"
        f"5. Новые договоры: {'вкл' if mod_contracts else 'выкл'}\n\n"
        "Выберите параметр для изменения:"
    )
    
    builder = InlineKeyboardBuilder()
    builder.button(text="1️⃣", callback_data="toggle_admin_questions")
    builder.button(text="2️⃣", callback_data="toggle_admin_contracts")
    builder.button(text="3️⃣", callback_data="toggle_admin_errors")
    builder.button(text="4️⃣", callback_data="toggle_mod_questions")
    builder.button(text="5️⃣", callback_data="toggle_mod_contracts")
    builder.button(text="⬅️ Назад", callback_data="admin_back")
    builder.adjust(3, 2, 1)
    
    try:
        await message.edit_text(text, reply_markup=builder.as_markup())
    except:
        await message.answer(text, reply_markup=builder.as_markup())

@dp.callback_query(F.data == "toggle_admin_questions")
async def toggle_admin_questions(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_admin_questions')

@dp.callback_query(F.data == "toggle_admin_contracts")
async def toggle_admin_contracts(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_admin_contracts')

@dp.callback_query(F.data == "toggle_admin_errors")
async def toggle_admin_errors(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_admin_errors')

@dp.callback_query(F.data == "toggle_mod_questions")
async def toggle_mod_questions(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_moderators_questions')

@dp.callback_query(F.data == "toggle_mod_contracts")
async def toggle_mod_contracts(callback: types.CallbackQuery):
    await toggle_notification_setting(callback, 'notify_moderators_contracts')

async def toggle_notification_setting(callback: types.CallbackQuery, setting_key: str):
    current = await is_notification_enabled(setting_key)
    new_value = not current
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
            "ON CONFLICT (key) DO UPDATE SET value = $2",
            setting_key, '1' if new_value else '0'
        )
    
    # Clear cache
    redis_client.delete(f'notification:{setting_key}')
    
    # Update message
    await update_notifications_message(callback.message)
    await callback.answer(f"Уведомления {'включены' if new_value else 'выключены'}")

async def display_contract(callback: types.CallbackQuery, contract: dict, contract_type: str, has_more: bool):
    try:
        if contract_type == "physical":
            try:
                # Расшифровка всех зашифрованных полей
                phone = decrypt_data(contract['phone'])
                passport_id = decrypt_data(contract['passport_id'])
            except Exception as e:
                logger.error(f"Failed to decrypt contract data: {e}", exc_info=True)
                phone = "[ошибка расшифровки]"
                passport_id = "[ошибка расшифровки]"
            
            text = (
                f"Договор физ. лица (ID: {contract['id']})\n\n"
                f"👤 Пользователь: {contract['username'] or contract['user_id']}\n"
                f"🆔 ID пользователя: {contract['user_id']}\n"
                f"📅 Дата создания: {contract['created_at']}\n\n"
                f"📝 Данные:\n"
                f"ФИО: {contract['full_name']}\n"
                f"Номер паспорта: {passport_id}\n"
                f"Дата выдачи: {contract['passport_issue_date']}\n"
                f"Кем выдан: {contract['passport_issued_by']}\n"
                f"Адрес проживания: {contract['living_address']}\n"
                f"Адрес регистрации: {contract['registration_address']}\n"
                f"Телефон: {phone}\n"
                f"Email: {contract['email']}"
            )
        else:
            try:
                # Расшифровка всех зашифрованных полей для юр.лица
                phone = decrypt_data(contract['phone'])
                okpo = decrypt_data(contract['okpo']) if contract['okpo'] else "не указано"
                unp = decrypt_data(contract['unp'])
                account = decrypt_data(contract['account_number'])
            except Exception as e:
                logger.error(f"Failed to decrypt contract data: {e}", exc_info=True)
                phone = "[ошибка расшифровки]"
                okpo = "[ошибка расшифровки]"
                unp = "[ошибка расшифровки]"
                account = "[ошибка расшифровки]"
            
            text = (
                f"Договор юр. лица (ID: {contract['id']})\n\n"
                f"👤 Пользователь: {contract['username'] or contract['user_id']}\n"
                f"🆔 ID пользователя: {contract['user_id']}\n"
                f"📅 Дата создания: {contract['created_at']}\n\n"
                f"📝 Данные:\n"
                f"Организация: {contract['organization_name']}\n"
                f"Почтовый адрес: {contract['postal_address']}\n"
                f"Юридический адрес: {contract['legal_address']}\n"
                f"Телефон: {phone}\n"
                f"Вид деятельности: {contract['activity_type']}\n"
                f"ОКПО: {okpo}\n"
                f"УНП: {unp}\n"
                f"Расчетный счет: {account}\n"
                f"Банк: {contract['bank_name']}\n"
                f"БИК: {contract['bank_bic']}\n"
                f"Адрес банка: {contract['bank_address']}\n"
                f"Подписант: {contract['signatory_name']}\n"
                f"Основание полномочий: {contract['authority_basis']}\n"
                f"Должность: {contract['position']}\n"
                f"Email: {contract['email']}"
            )
        
        # Check if there are more contracts
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            if contract_type == "physical":
                has_next = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_physical WHERE id > $1 AND status = 'pending')",
                    contract['id']
                )
                has_prev = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_physical WHERE id < $1 AND status = 'pending')",
                    contract['id']
                )
            else:
                has_next = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_legal WHERE id > $1 AND status = 'pending')",
                    contract['id']
                )
                has_prev = await conn.fetchval(
                    "SELECT EXISTS(SELECT 1 FROM contracts_legal WHERE id < $1 AND status = 'pending')",
                    contract['id']
                )
        
        await callback.message.edit_text(
            text,
            reply_markup=await get_contract_action_menu(contract['id'], contract_type, has_next, has_prev)
        )
        
    except Exception as e:
        logger.error(f"Failed to display contract: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Произошла ошибка при отображении договора.")

@dp.callback_query(F.data == "toggle_notify_contracts")
async def toggle_notify_contracts_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling contracts notifications")
    try:
        current = await is_button_enabled('notify_contracts')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'notify_contracts', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:notify_contracts')
        
        # Update message
        questions_notify = await is_button_enabled('notify_questions')
        contracts_notify = new_value
        errors_notify = await is_button_enabled('notify_errors')
        
        text = (
            "🔔 Настройки уведомлений:\n\n"
            f"1. Новые вопросы: {'вкл' if questions_notify else 'выкл'}\n"
            f"2. Новые договоры: {'вкл' if contracts_notify else 'выкл'}\n"
            f"3. Ошибки системы: {'вкл' if errors_notify else 'выкл'}\n\n"
            "Выберите параметр для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_notify_questions")
        builder.button(text="2️⃣", callback_data="toggle_notify_contracts")
        builder.button(text="3️⃣", callback_data="toggle_notify_errors")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(3, 1)
        
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle contracts notifications: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить настройки уведомлений.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "toggle_notify_errors")
async def toggle_notify_errors_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling errors notifications")
    try:
        current = await is_button_enabled('notify_errors')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'notify_errors', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:notify_errors')
        
        # Update message
        questions_notify = await is_button_enabled('notify_questions')
        contracts_notify = await is_button_enabled('notify_contracts')
        errors_notify = new_value
        
        text = (
            "🔔 Настройки уведомлений:\n\n"
            f"1. Новые вопросы: {'вкл' if questions_notify else 'выкл'}\n"
            f"2. Новые договоры: {'вкл' if contracts_notify else 'выкл'}\n"
            f"3. Ошибки системы: {'вкл' if errors_notify else 'выкл'}\n\n"
            "Выберите параметр для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_notify_questions")
        builder.button(text="2️⃣", callback_data="toggle_notify_contracts")
        builder.button(text="3️⃣", callback_data="toggle_notify_errors")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(3, 1)
        
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle errors notifications: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить настройки уведомлений.")
    finally:
        await callback.answer()

@dp.message(F.text == "🛠 Управление кнопками")
async def admin_buttons_handler(message: types.Message):
    logger.info(f"Admin {message.from_user.id} managing buttons")
    if not await is_admin(message.from_user.id):
        logger.warning(f"User {message.from_user.id} is not an admin")
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    try:
        # Get current button states
        consultation = await is_button_enabled('button_consultation')
        roi = await is_button_enabled('button_roi')
        experience = await is_button_enabled('button_experience')
        contract = await is_button_enabled('button_contract')
        questions = await is_button_enabled('button_unanswered_questions')
        contracts = await is_button_enabled('button_view_contracts')
        delayed = await is_button_enabled('button_delayed_messages')
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        
        await message.answer(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to get button states: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await message.answer("Произошла ошибка при получении состояния кнопок.")


	


@dp.callback_query(F.data == "toggle_button_consultation")
async def toggle_button_consultation_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling consultation button")
    try:
        current = await is_button_enabled('button_consultation')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'button_consultation', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:button_consultation')
        
        # Update message
        consultation = new_value
        roi = await is_button_enabled('button_roi')
        experience = await is_button_enabled('button_experience')
        contract = await is_button_enabled('button_contract')
        questions = await is_button_enabled('button_unanswered_questions')
        contracts = await is_button_enabled('button_view_contracts')
        delayed = await is_button_enabled('button_delayed_messages')
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle consultation button: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить состояние кнопки.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "toggle_button_roi")
async def toggle_button_roi_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling ROI button")
    try:
        current = await is_button_enabled('button_roi')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'button_roi', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:button_roi')
        
        # Update message
        consultation = await is_button_enabled('button_consultation')
        roi = new_value
        experience = await is_button_enabled('button_experience')
        contract = await is_button_enabled('button_contract')
        questions = await is_button_enabled('button_unanswered_questions')
        contracts = await is_button_enabled('button_view_contracts')
        delayed = await is_button_enabled('button_delayed_messages')
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle ROI button: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить состояние кнопки.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "toggle_button_experience")
async def toggle_button_experience_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling experience button")
    try:
        current = await is_button_enabled('button_experience')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'button_experience', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:button_experience')
        
        # Update message
        consultation = await is_button_enabled('button_consultation')
        roi = await is_button_enabled('button_roi')
        experience = new_value
        contract = await is_button_enabled('button_contract')
        questions = await is_button_enabled('button_unanswered_questions')
        contracts = await is_button_enabled('button_view_contracts')
        delayed = await is_button_enabled('button_delayed_messages')
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle experience button: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить состояние кнопки.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "toggle_button_contract")
async def toggle_button_contract_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling contract button")
    try:
        current = await is_button_enabled('button_contract')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'button_contract', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:button_contract')
        
        # Update message
        consultation = await is_button_enabled('button_consultation')
        roi = await is_button_enabled('button_roi')
        experience = await is_button_enabled('button_experience')
        contract = new_value
        questions = await is_button_enabled('button_unanswered_questions')
        contracts = await is_button_enabled('button_view_contracts')
        delayed = await is_button_enabled('button_delayed_messages')
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle contract button: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить состояние кнопки.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "toggle_button_unanswered_questions")
async def toggle_button_unanswered_questions(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling unanswered questions button")
    try:
        current = await is_button_enabled('button_unanswered_questions')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'button_unanswered_questions', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:button_unanswered_questions')
        
        # Update message
        consultation = await is_button_enabled('button_consultation')
        roi = await is_button_enabled('button_roi')
        experience = await is_button_enabled('button_experience')
        contract = await is_button_enabled('button_contract')
        questions = new_value
        contracts = await is_button_enabled('button_view_contracts')
        delayed = await is_button_enabled('button_delayed_messages')
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle unanswered questions button: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить состояние кнопки.")
    finally:
        await callback.answer()
		
@dp.callback_query(F.data == "toggle_button_view_contracts")
async def toggle_button_unanswered_questions(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling view contracts button")
    try:
        current = await is_button_enabled('button_view_contracts')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'button_view_contracts', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:button_view_contracts')
        
        # Update message
        consultation = await is_button_enabled('button_consultation')
        roi = await is_button_enabled('button_roi')
        experience = await is_button_enabled('button_experience')
        contract = await is_button_enabled('button_contract')
        questions = await is_button_enabled('button_unanswered_questions')
        contracts = new_value
        delayed = await is_button_enabled('button_delayed_messages')
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle view contracts button: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить состояние кнопки.")
    finally:
        await callback.answer()

@dp.callback_query(F.data == "toggle_button_delayed_messages")
async def toggle_button_unanswered_questions(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} toggling delayed messages button")
    try:
        current = await is_button_enabled('button_delayed_messages')
        new_value = not current
        
        pool = await get_db_connection()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO bot_settings (key, value) VALUES ($1, $2) "
                "ON CONFLICT (key) DO UPDATE SET value = $2",
                'button_delayed_messages', '1' if new_value else '0'
            )
        
        # Clear cache
        redis_client.delete('button:button_delayed_messages')
        
        # Update message
        consultation = await is_button_enabled('button_consultation')
        roi = await is_button_enabled('button_roi')
        experience = await is_button_enabled('button_experience')
        contract = await is_button_enabled('button_contract')
        questions = await is_button_enabled('button_unanswered_questions')
        contracts = await is_button_enabled('button_view_contracts')
        delayed = new_value
        
        text = (
            "🛠 Управление кнопками:\n\n"
			"📌 Для пользователей:\n"
            f"1. ❓ Консультация: {'вкл' if consultation else 'выкл'}\n"
            f"2. 💰 Расчёт окупаемости: {'вкл' if roi else 'выкл'}\n"
            f"3. 🎥📚Полезная информация: {'вкл' if experience else 'выкл'}\n"
            f"4. 📝 Договор: {'вкл' if contract else 'выкл'}\n\n"
			"📌 Для модераторов:\n"
            f"5. 📋 Неотвеченные вопросы: {'вкл' if questions else 'выкл'}\n"
            f"6. 📝 Просмотреть договоры: {'вкл' if contracts else 'выкл'}\n"
            f"7. ⏱ Отложенные сообщения: {'вкл' if delayed else 'выкл'}\n\n"
            "Выберите кнопку для изменения:"
        )
        
        builder = InlineKeyboardBuilder()
        builder.button(text="1️⃣", callback_data="toggle_button_consultation")
        builder.button(text="2️⃣", callback_data="toggle_button_roi")
        builder.button(text="3️⃣", callback_data="toggle_button_experience")
        builder.button(text="4️⃣", callback_data="toggle_button_contract")
        builder.button(text="5️⃣", callback_data="toggle_button_unanswered_questions")
        builder.button(text="6️⃣", callback_data="toggle_button_view_contracts")
        builder.button(text="7️⃣", callback_data="toggle_button_delayed_messages")
        builder.button(text="⬅️ Назад", callback_data="admin_back")
        builder.adjust(4, 3, 1)
        await callback.message.edit_text(
            text,
            reply_markup=builder.as_markup()
        )
        
    except Exception as e:
        logger.error(f"Failed to toggle delayed messages button: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
        await callback.message.answer("Не удалось изменить состояние кнопки.")
    finally:
        await callback.answer()
		
# Обработчик управления отложенными сообщениями
@dp.message(F.text == "⏱ Управление отлож. сообщениями")
async def manage_delayed_messages(message: types.Message):
    if not await is_admin(message.from_user.id):
        await message.answer("У вас нет доступа к этой функции.")
        return
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        messages = await conn.fetch(
            "SELECT * FROM delayed_messages "
            "WHERE status IN ('pending', 'approved') "
            "ORDER BY send_time LIMIT 10"
        )
        
        if not messages:
            await message.answer("Нет отложенных сообщений для управления.")
            return
        
        for msg in messages:
            text = (
                f"📨 Отложенное сообщение ID: {msg['id']}\n"
                f"Статус: {msg['status']}\n"
                f"Тип: {msg['content_type']}\n"
                f"Время отправки: {msg['send_time'].strftime('%d.%m.%Y %H:%M')}\n"
                f"Получатели: {msg['recipient_type']}"
            )
            
            if msg['text_content']:
                text += f"\n\nТекст: {msg['text_content']}"
            
            builder = InlineKeyboardBuilder()
            if msg['status'] == 'pending':
                builder.button(text="✅ Одобрить", callback_data=f"approve_msg_{msg['id']}")
                builder.button(text="❌ Отклонить", callback_data=f"reject_msg_{msg['id']}")
            else:
                builder.button(text="🚫 Отменить отправку", callback_data=f"block_msg_{msg['id']}")
                builder.button(text="👁️ Скрыть", callback_data=f"hide_msg_{msg['id']}")
                builder.adjust(2, 1)
            
            try:
                if msg['photo_path'] and os.path.exists(msg['photo_path']):
                    with open(msg['photo_path'], 'rb') as photo:
                        photo_bytes = photo.read()
                    input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
                    await message.answer_photo(
                        input_file,
                        caption=text,
                        reply_markup=builder.as_markup()
                    )
                else:
                    await message.answer(
                        text,
                        reply_markup=builder.as_markup()
                    )
            except Exception as e:
                logger.error(f"Failed to show message {msg['id']}: {e}", exc_info=True)
                await message.answer(
                    f"Ошибка при отображении сообщения {msg['id']}",
                    reply_markup=builder.as_markup()
                )

# Обработчики действий администратора
@dp.callback_query(F.data.startswith("hide_msg_"))
async def hide_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    try:
        # Просто удаляем сообщение без изменения статуса
        await callback.message.delete()
        await callback.answer("Сообщение скрыто", show_alert=False)
    except Exception as e:
        logger.error(f"Failed to hide message: {e}", exc_info=True)
        await callback.answer("Не удалось скрыть сообщение", show_alert=True)
		
@dp.callback_query(F.data.startswith("approve_msg_"))
async def approve_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_data = await conn.fetchrow(
            "SELECT * FROM delayed_messages WHERE id = $1",
            message_id
        )
        
        await conn.execute(
            "UPDATE delayed_messages SET status = 'approved', approved_by = $1, approved_at = CURRENT_TIMESTAMP WHERE id = $2",
            callback.from_user.id,
            message_id
        )
    
    # Удаляем исходное сообщение
    try:
        await callback.message.delete()
    except Exception as e:
        logger.error(f"Failed to delete message: {e}", exc_info=True)
    await callback.answer("Сообщение одобрено", show_alert=False)
    
    # Уведомляем модератора
    if message_data['created_by']:
        try:
            await bot.send_message(
                message_data['created_by'],
                f"✅ Ваше отложенное сообщение (ID: {message_id}) было одобрено администратором."
            )
        except Exception as e:
            logger.error(f"Failed to notify moderator: {e}", exc_info=True)
    
    # Отправляем подтверждение админу в новом сообщении
    await callback.message.answer(
        f"Сообщение {message_id} одобрено и будет отправлено в указанное время."
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("reject_msg_"))
async def reject_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_data = await conn.fetchrow(
            "SELECT * FROM delayed_messages WHERE id = $1",
            message_id
        )
        
        if message_data.get('photo_path'):
            try:
                os.remove(message_data['photo_path'])
            except:
                pass
        
        await conn.execute(
            "UPDATE delayed_messages SET status = 'rejected' WHERE id = $1",
            message_id
        )
    
    # Удаляем исходное сообщение
    try:
        await callback.message.delete()
    except Exception as e:
        logger.error(f"Failed to delete message: {e}", exc_info=True)
    await callback.answer("Сообщение отклонено", show_alert=False)
	
    # Уведомляем модератора
    if message_data['created_by']:
        try:
            await bot.send_message(
                message_data['created_by'],
                f"❌ Ваше отложенное сообщение (ID: {message_id}) было отклонено администратором."
            )
        except Exception as e:
            logger.error(f"Failed to notify moderator: {e}", exc_info=True)
    
    # Отправляем подтверждение админу в новом сообщении
    await callback.message.answer(
        f"Сообщение {message_id} отклонено."
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("reject_msg_"))
async def reject_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message = await conn.fetchrow("SELECT photo_path FROM delayed_messages WHERE id = $1", message_id)
        if message and message['photo_path']:
            try:
                os.remove(message['photo_path'])
            except:
                pass
        
        await conn.execute(
            "UPDATE delayed_messages SET status = 'rejected' WHERE id = $1",
            message_id
        )
    
    await callback.message.edit_text(
        f"Сообщение {message_id} отклонено.",
        reply_markup=None
    )
    await callback.answer()

@dp.callback_query(F.data.startswith("block_msg_"))
async def block_message(callback: types.CallbackQuery):
    message_id = int(callback.data.split("_")[2])
    
    pool = await get_db_connection()
    async with pool.acquire() as conn:
        message_data = await conn.fetchrow(
            "SELECT * FROM delayed_messages WHERE id = $1",
            message_id
        )
        
        await conn.execute(
            "UPDATE delayed_messages SET status = 'blocked' WHERE id = $1",
            message_id
        )
    
    # Удаляем исходное сообщение
    try:
        await callback.message.delete()
    except Exception as e:
        logger.error(f"Failed to delete message: {e}", exc_info=True)
    await callback.answer("Отправка сообщения отменена", show_alert=False)
    
    # Уведомляем модератора
    if message_data['created_by']:
        try:
            await bot.send_message(
                message_data['created_by'],
                f"🚫 Отправка вашего отложенного сообщения (ID: {message_id}) была отменена администратором."
            )
        except Exception as e:
            logger.error(f"Failed to notify moderator: {e}", exc_info=True)
    
    # Отправляем подтверждение админу в новом сообщении
    await callback.message.answer(
        f"Отправка сообщения {message_id} отменена."
    )
    await callback.answer()
async def send_scheduled_messages():
    while True:
        try:
            pool = await get_db_connection()
            async with pool.acquire() as conn:
                messages = await conn.fetch(
                    "SELECT * FROM delayed_messages "
                    "WHERE status = 'approved' AND send_time <= CURRENT_TIMESTAMP"
                )
                
                for msg in messages:
                    try:
                        if not msg['text_content'] and msg['content_type'] in ['text', 'photo_with_text']:
                            await conn.execute(
                                "UPDATE delayed_messages SET status = 'failed' WHERE id = $1",
                                msg['id']
                            )
                            continue
                            
                        if msg['recipient_type'] == 'all':
                            users = await conn.fetch("SELECT user_id FROM users")
                            recipient_ids = [u['user_id'] for u in users]
                        elif msg['recipient_type'] == 'moderators':
                            recipient_ids = config.MODERATOR_IDS + [config.ADMIN_ID]
                        else:
                            recipient_ids = [msg['recipient_id']]
                        
                        success = True
                        for user_id in recipient_ids:
                            try:
                                if msg['content_type'] == 'text' and msg['text_content']:
                                    await bot.send_message(user_id, msg['text_content'])
                                elif msg['content_type'] == 'photo' and msg['photo_path']:
                                    # Исправлено: используем BufferedInputFile
                                    with open(msg['photo_path'], 'rb') as photo_file:
                                        photo_bytes = photo_file.read()
                                    input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
                                    await bot.send_photo(user_id, input_file)
                                elif msg['content_type'] == 'photo_with_text' and msg['photo_path'] and msg['text_content']:
                                    # Исправлено: используем BufferedInputFile
                                    with open(msg['photo_path'], 'rb') as photo_file:
                                        photo_bytes = photo_file.read()
                                    input_file = BufferedInputFile(photo_bytes, filename="photo.jpg")
                                    await bot.send_photo(user_id, input_file, caption=msg['text_content'])
                            except Exception as e:
                                logger.error(f"Failed to send message {msg['id']} to user {user_id}: {e}", exc_info=True)
                                success = False
                                break
                        
                        if success:
                            await conn.execute(
                                "UPDATE delayed_messages SET status = 'sent' WHERE id = $1",
                                msg['id']
                            )
                            if msg.get('photo_path'):
                                try:
                                    os.remove(msg['photo_path'])
                                except:
                                    pass
                        else:
                            attempts = msg.get('attempts', 0) + 1
                            if attempts >= 3:
                                await conn.execute(
                                    "UPDATE delayed_messages SET status = 'failed' WHERE id = $1",
                                    msg['id']
                                )
                            else:
                                await conn.execute(
                                    "UPDATE delayed_messages SET attempts = $1 WHERE id = $2",
                                    attempts,
                                    msg['id']
                                )
                    except Exception as e:
                        logger.error(f"Error processing message {msg['id']}: {e}", exc_info=True)
                        await conn.execute(
                            "UPDATE delayed_messages SET status = 'failed' WHERE id = $1",
                            msg['id']
                        )
            
            await asyncio.sleep(60)
        except Exception as e:
            logger.error(f"Error in send_scheduled_messages: {e}", exc_info=True)
            await asyncio.sleep(300)

@dp.callback_query(F.data == "admin_back")
async def admin_back_handler(callback: types.CallbackQuery):
    logger.info(f"Admin {callback.from_user.id} returning to admin menu")
    await callback.message.edit_text(
        "Возвращаемся в админ-панель",
        reply_markup=None
    )
    await callback.message.answer(
        "Админ-панель:",
        reply_markup=await get_admin_menu()
    )
    await callback.answer()

@dp.message(F.text == "⬅️ Главное меню")
async def back_to_main_handler(message: types.Message):
    logger.info(f"User {message.from_user.id} returning to main menu")
    await message.answer(
        "Главное меню:",
        reply_markup=await get_main_menu(message.from_user.id)
    )

# Error handler
@dp.error()
async def error_handler(event: types.ErrorEvent):
    logger.error(f"Unhandled error: {event.exception}", exc_info=True)
    sentry_sdk.capture_exception(event.exception)
    
    if isinstance(event.update, types.Message):
        await event.update.answer("Произошла непредвиденная ошибка. Пожалуйста, попробуйте позже.")

# Startup and shutdown
async def on_startup():
	
    logger.info("Bot starting up...")
    asyncio.create_task(send_scheduled_messages())
    await init_db()
    await notify_admins("Бот запущен и готов к работе", EMOJI_INFO)
    
    # Start FastAPI server in background
    if os.getenv("RUN_WEB", "true").lower() == "true":
        uvicorn_config = uvicorn.Config(  # Используйте другое имя переменной
            app,
            host=config.WEB_HOST,
            port=config.WEB_PORT,
            log_level="info"
        )
        server = uvicorn.Server(uvicorn_config)
        asyncio.create_task(server.serve())

async def on_shutdown():
    logger.info("Bot shutting down...")
    await notify_admins("Бот выключается", EMOJI_WARNING)
    await bot.session.close()
    if db_pool:
        await db_pool.close()
    redis_client.close()

# Main function
async def main():
    logger.info("Starting bot...")
    
    dp.startup.register(on_startup)
    dp.shutdown.register(on_shutdown)
    
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot stopped")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sentry_sdk.capture_exception(e)
