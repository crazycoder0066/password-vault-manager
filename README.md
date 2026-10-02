# Password vault manager

A local Django browser app for storing passwords in an encrypted vault and manually rotating them. Requires Python 3.11+ on Linux or macOS.

## Setup

```sh
uv sync --locked
```

Select `.venv/bin/python` as your IDE interpreter. Manage dependencies with `uv add` and `uv remove`.

## Run

```sh
uv run --locked password-vault-manager --port 8000
```

Open http://127.0.0.1:8000. The Django development server listens on loopback only. `GET /health` provides a health check. The existing UI and `/api/` routes are served by Django. The Django admin, database, and session framework are not used; vault data remains in the encrypted file.

1. Create a vault with a master passphrase of at least 12 characters.
2. Add an account name, username, website, password, and rotation interval. Use **Generate password** for a random 24-character password.
3. Search saved accounts or use **Reveal** to show a password for 30 seconds.
4. Use **Rotate** to prepare a replacement. Apply it to the corresponding account, then choose **Save replacement**.
5. Use **Lock vault** when finished. The vault also locks after five minutes without vault API activity. Change the master password in the settings panel.
6. Use **Export encrypted vault** to download a `.vault` backup. To merge entries from a backup or another installation, select its `.vault` file under **Encrypted backup**, enter that file's master password, and choose **Import entries**. Existing entries are kept. An entry with the same ID and different contents is imported with a new ID; exact matches are skipped.

Rotation reminders do not update passwords on external services. The default file is `data/passwords.vault` relative to the working directory. To choose another location:

```sh
uv run --locked password-vault-manager --vault /path/to/passwords.vault
```

Back up this encrypted file. There is no master password recovery. Only one server process can open a given vault file, and one browser session can unlock it at a time. Run a single local server process; do not deploy it under a multiprocess WSGI or ASGI server.

Exports use the same encrypted format as the on-disk vault. You need the master password that protected the file when it was exported, even if you later change the current vault's master password. Imports accept this app's encrypted `.vault` files, up to 8 MiB; they do not accept CSV or plaintext password lists. A failed import leaves the current vault unchanged.

## Storage and access

The vault file format is unchanged from the prior app. It uses AES-256-GCM with a random nonce per write and a key derived via scrypt (N=32768, r=8, p=1, random 16-byte salt). Account metadata and passwords are encrypted together. Writes atomically replace the owner-only file.

The HTTP interface uses an HttpOnly, SameSite=Strict session cookie, checks local Host and Origin headers, and requires a custom header on API POST requests. Responses disable caching. Five failed unlock attempts trigger a 30-second cooldown.

The vault directory must be owned by your OS user and private (mode `0700`), and an existing vault file must be a regular file owned by you with mode `0600`. Symlinked vault files are rejected. The lock file is kept at mode `0600`. If you choose a custom `--vault` path, create its parent directory with private permissions first.

This is a local app, not an audited password manager. Keep it on loopback. Secrets exist in process and browser memory while unlocked.

## Validate

```sh
uv run --locked python -m unittest discover -s tests -v
```
