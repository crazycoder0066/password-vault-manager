"""Django views preserving the browser app's JSON API."""
import json
import secrets
import time
from importlib.resources import files

from django.http import HttpResponse, JsonResponse
from django.views.decorators.http import require_GET, require_POST

from .runtime import get_runtime
from .vault import VaultAuthenticationError, VaultEntry, VaultLockedError, generate_password


def error(status, message):
    return JsonResponse({"error": message}, status=status)


def asset(request, name):
    if request.method != "GET":
        return error(405, "Method not allowed")
    content_type = {"index.html": "text/html", "app.js": "text/javascript", "style.css": "text/css"}[name]
    body = files("password_vault_manager").joinpath("static", name).read_bytes()
    return HttpResponse(body, content_type=content_type + "; charset=utf-8")


@require_GET
def health(request):
    return JsonResponse({"status": "ok", "service": "password-vault-manager"})


@require_GET
def status(request):
    runtime = get_runtime()
    with runtime.mutex:
        return JsonResponse({"initialized": runtime.store.initialized,
                             "locked": not runtime.authenticated(request.COOKIES.get("vault_session"))})


def text(data, name, default=""):
    value = data.get(name, default)
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    return value


def authenticated_runtime(request):
    runtime = get_runtime()
    if not runtime.authenticated(request.COOKIES.get("vault_session")):
        raise VaultLockedError("Unlock the vault first")
    return runtime


@require_POST
def export_vault(request):
    if request.META.get("HTTP_X_VAULT_REQUEST") != "1":
        return error(403, "Missing vault request header")
    runtime = get_runtime()
    with runtime.mutex:
        try:
            authenticated_runtime(request)
            blob = runtime.store.export_encrypted()
        except VaultLockedError as exc:
            return error(401, str(exc))
        except (OSError, ValueError):
            return error(500, "Could not export the vault file")
    response = HttpResponse(blob, content_type="application/octet-stream")
    response["Content-Disposition"] = 'attachment; filename="passwords.vault"'
    return response


@require_POST
def import_vault(request):
    if request.META.get("HTTP_X_VAULT_REQUEST") != "1":
        return error(403, "Missing vault request header")
    try:
        length = int(request.META.get("CONTENT_LENGTH", "0"))
    except ValueError:
        return error(400, "Invalid upload size")
    if not 0 < length <= 9 * 1024 * 1024:
        return error(400, "Encrypted vault upload must be at most 8 MiB")
    runtime = get_runtime()
    with runtime.mutex:
        try:
            authenticated_runtime(request)
            upload = request.FILES.get("vault_file")
            master_password = request.POST.get("master_password", "")
            if upload is None or upload.size > 8 * 1024 * 1024 or not master_password:
                raise ValueError("Choose an encrypted vault and enter its master password")
            added = runtime.store.import_encrypted(upload.read(), master_password)
            return JsonResponse({"imported": added})
        except VaultLockedError as exc:
            return error(401, str(exc))
        except VaultAuthenticationError:
            return error(400, "Incorrect import password or damaged vault file")
        except (ValueError, TypeError) as exc:
            return error(400, str(exc))
        except OSError:
            return error(500, "Could not import the vault file")


@require_POST
def api(request, action):
    if request.META.get("HTTP_X_VAULT_REQUEST") != "1":
        return error(403, "Missing vault request header")
    if request.content_type != "application/json":
        return error(415, "Use application/json")
    try:
        length = int(request.META.get("CONTENT_LENGTH", "0"))
        if not 0 < length <= 32768:
            raise ValueError("Request size must be between 1 and 32768 bytes")
        data = json.loads(request.body)
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object")
        runtime = get_runtime()
        with runtime.mutex:
            return dispatch(runtime, request, action, data)
    except VaultAuthenticationError as exc:
        with runtime.mutex:
            runtime.lock_vault()
            runtime.failures += 1
            if runtime.failures >= 5:
                runtime.retry_after = time.monotonic() + 30
        return error(401, str(exc))
    except VaultLockedError as exc:
        return error(401, str(exc))
    except KeyError:
        return error(404, "Entry not found")
    except (ValueError, TypeError) as exc:
        return error(400, str(exc))
    except OSError:
        return error(500, "Could not read or write the vault file")


def dispatch(runtime, request, action, data):
    store = runtime.store
    token = request.COOKIES.get("vault_session")
    if action in ("create", "unlock"):
        if time.monotonic() < runtime.retry_after:
            return error(429, "Too many unlock attempts; wait 30 seconds")
        if runtime.session and not runtime.authenticated(token) and not store.locked:
            return error(409, "Vault is already open in another browser session")
        password = text(data, "master_password")
        (store.initialize if action == "create" else store.unlock)(password)
        runtime.session = secrets.token_urlsafe(32)
        runtime.last_activity = time.monotonic()
        runtime.failures = 0
        response = JsonResponse({"ok": True})
        response.set_cookie("vault_session", runtime.session, httponly=True, samesite="Strict", path="/")
        return response
    if not runtime.authenticated(token):
        raise VaultLockedError("Unlock the vault first")
    if action == "lock":
        runtime.lock_vault()
        response = JsonResponse({"ok": True})
        response.delete_cookie("vault_session", path="/", samesite="Strict")
        return response
    if action == "entries":
        return JsonResponse({"entries": [store.get(key).summary() for key in store.list_ids()]})
    if action == "generate":
        return JsonResponse({"password": generate_password()})
    if action == "save":
        entry = VaultEntry(secrets.token_hex(16), text(data, "title"), text(data, "username"),
                           text(data, "password"), text(data, "url"),
                           rotation_days=data.get("rotation_days", 90))
        store.save(entry)
        return JsonResponse({"entry": entry.summary()}, status=201)
    if action == "reveal":
        return JsonResponse({"password": store.get(text(data, "id")).password})
    if action == "rotate":
        entry = store.rotate(text(data, "id"), text(data, "password"))
        return JsonResponse({"entry": entry.summary(), "password": entry.password})
    if action == "delete":
        store.delete(text(data, "id"))
        return JsonResponse({"ok": True})
    if action == "master-password":
        store.change_master_password(text(data, "master_password"))
        return JsonResponse({"ok": True})
    return error(404, "Not found")
