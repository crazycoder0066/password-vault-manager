#!/usr/bin/env python3
"""Django management entry point."""
import os
from django.core.management import execute_from_command_line

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "password_vault_manager.settings")
    execute_from_command_line()
