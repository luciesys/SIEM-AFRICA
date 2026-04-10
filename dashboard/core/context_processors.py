from . import db as DB

def siem_context(request):
    ctx = {
        'user_id':    request.session.get('user_id'),
        'username':   request.session.get('username', ''),
        'role':       request.session.get('role', ''),
        'lang':       request.session.get('lang', 'fr'),
        'is_admin':   request.session.get('role') == 'admin_securite',
    }
    if ctx['user_id']:
        try:
            s = DB.get_stats()
            ctx['nb_critiques'] = s.get('critiques_actives', 0)
            ctx['nb_hautes']    = s.get('hautes_actives', 0)
            ctx['nb_inconnues'] = s.get('inconnues', 0)
        except Exception:
            ctx['nb_critiques'] = 0
            ctx['nb_hautes']    = 0
            ctx['nb_inconnues'] = 0
    return ctx
