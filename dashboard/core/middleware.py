"""
Middleware d'authentification SIEM Africa
Protege toutes les URLs sauf /login/
"""
from django.shortcuts import redirect
from django.urls import reverse

PUBLIC = ['/login/', '/favicon.ico']

class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        path = request.path
        if any(path.startswith(p) for p in PUBLIC) or path.startswith('/static/'):
            return self.get_response(request)

        if not request.session.get('user_id'):
            return redirect(f'/login/?next={path}')

        # Forcer changement credentials a la premiere connexion
        if request.session.get('premiere_connexion') and path != '/premiere-connexion/':
            return redirect('/premiere-connexion/')

        return self.get_response(request)
