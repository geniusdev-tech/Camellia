import os


class Config:
    SECRET_KEY              = os.getenv("SECRET_KEY")
    SESSION_COOKIE_SECURE   = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    PERMANENT_SESSION_LIFETIME = int(os.getenv("SESSION_LIFETIME", 300))


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE   = False
    SESSION_COOKIE_SAMESITE = "Lax"


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
