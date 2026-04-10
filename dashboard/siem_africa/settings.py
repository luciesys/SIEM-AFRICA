import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

def _env(key, default=''):
    env_file = '/opt/siem-africa/.env'
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line.startswith(f'{key}='):
                    return line.split('=', 1)[1].strip().strip('"').strip("'")
    return os.environ.get(key, default)

SECRET_KEY    = _env('SECRET_KEY', 'siem-africa-key-changez-moi')
DEBUG         = False
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.staticfiles',
    'django.contrib.sessions',
    'django.contrib.messages',
    'core',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'core.middleware.AuthMiddleware',
]

ROOT_URLCONF = 'siem_africa.urls'

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [BASE_DIR / 'templates'],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': [
        'django.template.context_processors.request',
        'django.contrib.messages.context_processors.messages',
        'core.context_processors.siem_context',
    ]},
}]

WSGI_APPLICATION = 'siem_africa.wsgi.application'
DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3',
                          'NAME': BASE_DIR / 'db_sessions.sqlite3'}}

SESSION_ENGINE          = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE      = 7200
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_NAME     = 'siem_session'

STATIC_URL       = '/static/'
STATIC_ROOT      = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [BASE_DIR / 'static']
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

SIEM_DB_PATH  = _env('DB_PATH', '/opt/siem-africa/siem_africa.db')
SIEM_LANG_DEF = _env('LANG', 'fr')
SIEM_VERSION  = '2.0'
