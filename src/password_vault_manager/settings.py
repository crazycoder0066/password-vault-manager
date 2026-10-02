"""Settings for the loopback-only Django vault application."""
import secrets

SECRET_KEY = secrets.token_urlsafe(32)
DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
ROOT_URLCONF = "password_vault_manager.urls"
INSTALLED_APPS = []
MIDDLEWARE = ["password_vault_manager.middleware.LocalSecurityMiddleware"]
USE_TZ = True
DEFAULT_CHARSET = "utf-8"
LOGGING = {"version": 1, "disable_existing_loggers": False,
           "loggers": {"django.server": {"handlers": ["null"], "propagate": False}},
           "handlers": {"null": {"class": "logging.NullHandler"}}}
