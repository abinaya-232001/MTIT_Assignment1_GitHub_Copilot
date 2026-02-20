import os
from pydantic import AnyUrl
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: AnyUrl = "sqlite:///./test.db"  # default to sqlite for quick start
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SECRET_KEY: str = "CHANGE_ME_IN_PRODUCTION"
    ALGORITHM: str = "HS256"
    MAX_FAILED_LOGINS: int = 5
    LOCK_TIME_MINUTES: int = 15

    class Config:
        env_file = ".env"


settings = Settings()
