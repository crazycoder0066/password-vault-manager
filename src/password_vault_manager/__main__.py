"""Run the Django app on loopback with a single vault process."""
import argparse
import os

import django
from django.core.management import call_command

from .runtime import configure, reset_for_tests


def main():
    parser = argparse.ArgumentParser(description="Run the local encrypted password vault")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--vault", default="data/passwords.vault", help="Encrypted vault file")
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "password_vault_manager.settings")
    django.setup()
    try:
        configure(args.vault)
    except OSError as exc:
        parser.exit(1, f"Could not start vault server: {exc}\n")
    try:
        print(f"password-vault-manager running at http://127.0.0.1:{args.port}")
        call_command("runserver", f"127.0.0.1:{args.port}", use_reloader=False, use_threading=True)
    finally:
        reset_for_tests()


if __name__ == "__main__":
    main()
