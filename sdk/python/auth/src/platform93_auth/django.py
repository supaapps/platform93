from django.http import JsonResponse

from .verifier import Verifier


class Platform93AuthenticationMiddleware:
    def __init__(self, get_response, verifier: Verifier | None = None):
        self.get_response = get_response
        self.verifier = verifier

    def __call__(self, request):
        authorization = request.headers.get("Authorization", "")
        if authorization.lower().startswith("bearer ") and self.verifier:
            try:
                request.platform93_claims = self.verifier.verify(authorization[7:].strip())
            except Exception:
                return JsonResponse({"detail": "Invalid bearer token"}, status=401)
        return self.get_response(request)
