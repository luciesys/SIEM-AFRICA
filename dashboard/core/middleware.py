from django.shortcuts import redirect
from django.urls import resolve

PUBLIC_URLS = ['login', 'set_lang']

class AuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        try:
            url_name = resolve(request.path_info).url_name
        except Exception:
            url_name = ''

        if url_name not in PUBLIC_URLS and not request.session.get('user_id'):
            return redirect('login')

        return self.get_response(request)
