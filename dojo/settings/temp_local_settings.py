# local_settings.py
# this file will be included by settings.py *after* loading settings.dist.py

# this example configures the django debug toolbar and sets some loglevels to DEBUG

from pathlib import Path

import debug_toolbar
from django.conf import settings
from django.conf.urls import include
from django.urls import re_path

# UPDATE: Adding debug_toolbar to to INSTALLED_APPS here prevents the nginx container from generating the correct static files
#         So add debug_toolbar to INSTALLED_APPS in settings.dist.py and rebuild to get started with the debug_toolbar.
#         Thje middleware and other config can remain in this file (local_settings.py) to avoid chance of conflicts on upgrades.
settings.INSTALLED_APPS += (
#    'debug_toolbar',
)

MIDDLEWARE = [
    "debug_toolbar.middleware.DebugToolbarMiddleware",
    *settings.MIDDLEWARE,
]

LOGGING = settings.LOGGING.copy()

# adding DEBUG logging for all of Django.
LOGGING["loggers"]["root"] = {
            "handlers": ["console"],
            "level": "DEBUG",
        }
# setting log level WARN for defect dojo
# LOGGING['loggers']['dojo']['level'] = 'WARN'

# output DEBUG logging for deduplication
# LOGGING['loggers']['dojo.specific-loggers.deduplication']['level'] = 'DEBUG'


def show_toolbar(request):
    return True


DEBUG_TOOLBAR_CONFIG = {
    "SHOW_TOOLBAR_CALLBACK": show_toolbar,
    "INTERCEPT_REDIRECTS": False,
    "SHOW_COLLAPSED": True,
}

DEBUG_TOOLBAR_PANELS = [
    # 'ddt_request_history.panels.request_history.RequestHistoryPanel',  # Here it is
    "debug_toolbar.panels.versions.VersionsPanel",
    "debug_toolbar.panels.timer.TimerPanel",
    "debug_toolbar.panels.settings.SettingsPanel",
    "debug_toolbar.panels.headers.HeadersPanel",
    "debug_toolbar.panels.request.RequestPanel",
    "debug_toolbar.panels.sql.SQLPanel",
    "debug_toolbar.panels.templates.TemplatesPanel",
    # 'debug_toolbar.panels.staticfiles.StaticFilesPanel',
    "debug_toolbar.panels.cache.CachePanel",
    "debug_toolbar.panels.signals.SignalsPanel",
    "debug_toolbar.panels.logging.LoggingPanel",
    "debug_toolbar.panels.redirects.RedirectsPanel",
    "debug_toolbar.panels.profiling.ProfilingPanel",
    # 'cachalot.panels.CachalotPanel',
]

BASE_DIR = Path(__file__).resolve().parent.parent

SCAN_REPORTS_DIR = BASE_DIR / "uploads" / "scan_reports"

FILE_UPLOAD_MAX_MEMORY_SIZE = 2621440  # 2.5 MB
FILE_UPLOAD_TEMP_DIR = BASE_DIR / "tmp"

EXTRA_URL_PATTERNS = [re_path(r"^__debug__/", include(debug_toolbar.urls))]
