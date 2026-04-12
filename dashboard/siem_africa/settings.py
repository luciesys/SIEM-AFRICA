"""
SIEM Africa — Django Settings
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY', 'SECRET_KEY_PLACEHOLDER')

DEBUG = False

ALLOWED_HOSTS = [
    'SERVER_IP_PLACEHOLDER',
    'localhost',
    '127.0.0.1',
    '*',
]

INSTALLED_APPS = [
    'django.contrib.staticfiles',
    'django.contrib.sessions',
    'django.contrib.messages',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'core.middleware.AuthMiddleware',
]

ROOT_URLCONF = 'siem_africa.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
                'core.context_processors.siem_context',
            ],
        },
    },
]

WSGI_APPLICATION = 'siem_africa.wsgi.application'

# Base SQLite SIEM Africa (pas la base Django standard)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'DB_PATH_PLACEHOLDER',
    }
}

# Sessions en fichier (pas de base Django)
SESSION_ENGINE = 'django.contrib.sessions.backends.file'
SESSION_FILE_PATH = '/tmp/siem-sessions'
SESSION_COOKIE_AGE = 28800  # 8 heures
SESSION_COOKIE_HTTPONLY = True

STATIC_URL  = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Langues supportees
from django.utils.translation import gettext_lazy as _
LANGUAGE_CODE = 'fr'
LANGUAGES = [
    ('fr', _('Français')),
    ('en', _('English')),
]
USE_I18N = True
USE_TZ   = False
TIME_ZONE = 'Africa/Douala'

# Chemins SIEM Africa
SIEM_DB_PATH   = 'DB_PATH_PLACEHOLDER'
SIEM_ENV_FILE  = '/opt/siem-africa/.env'
SIEM_CRED_FILE = '/opt/siem-africa/credentials.txt'
SIEM_LOG_FILE  = '/var/log/siem-africa/dashboard.log'

# Messages
MESSAGE_STORAGE = 'django.contrib.messages.storage.cookie.CookieStorage'

# Securite
CSRF_COOKIE_HTTPONLY = True
X_FRAME_OPTIONS = 'DENY'

os.makedirs('/tmp/siem-sessions', exist_ok=True)
