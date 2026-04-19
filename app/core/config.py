from dotenv import load_dotenv
from pathlib import Path
import os
env_path = Path(__file__).resolve().parent / ".env" ; load_dotenv(dotenv_path=env_path)

DATABASE = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")