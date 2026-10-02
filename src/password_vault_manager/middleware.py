"""Require loopback browser origins and prevent caching of vault responses."""
from django.http import JsonResponse
from django.core.exceptions import DisallowedHost


class LocalSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            host = request.get_host()
        except DisallowedHost:
            host = ""
        origin = request.META.get("HTTP_ORIGIN")
        name, separator, port = host.partition(":")
        allowed_host = (bool(request.META.get("HTTP_HOST")) and name in {"127.0.0.1", "localhost"}
                        and (not separator or port.isdecimal() and 1 <= int(port) <= 65535))
        if (not allowed_host or (origin is not None and origin != f"http://{host}")
                or request.META.get("HTTP_SEC_FETCH_SITE") not in (None, "same-origin", "none")):
            response = JsonResponse({"error": "Request must come from the local vault page"}, status=403)
        else:
            response = self.get_response(request)
        response["Cache-Control"] = "no-store"
        response["X-Content-Type-Options"] = "nosniff"
        response["Referrer-Policy"] = "no-referrer"
        response["X-Frame-Options"] = "DENY"
        response["Cross-Origin-Opener-Policy"] = "same-origin"
        response["Cross-Origin-Resource-Policy"] = "same-origin"
        response["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; object-src 'none'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response
