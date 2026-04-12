from django.conf import settings

def siem_context(request):
    return {
        'user_role': request.session.get('user_role', ''),
        'user_name': request.session.get('user_name', ''),
        'user_id':   request.session.get('user_id'),
        'langue':    request.session.get('langue', 'fr'),
        'theme':     request.session.get('theme', 'dark'),
        'version':   '3.0',
    }
