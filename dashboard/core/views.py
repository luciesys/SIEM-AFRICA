"""
SIEM Africa — Module 4 : Vues Django
"""
import datetime
import json
import subprocess
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.http import require_POST
from django.contrib import messages

from . import db as DB
from .i18n import get_all as T

# ── Helpers ───────────────────────────────────────────────────────
def get_lang(request):
    return request.session.get('lang', 'fr')

def admin_only(view_func):
    def wrapper(request, *args, **kwargs):
        if request.session.get('role') != 'admin_securite':
            return HttpResponseForbidden('Acces refuse — role admin_securite requis')
        return view_func(request, *args, **kwargs)
    return wrapper

def ctx(request, extra=None):
    lang = get_lang(request)
    base = {'T': T(lang), 'lang': lang}
    if extra:
        base.update(extra)
    return base


# ── Authentification ──────────────────────────────────────────────
def login_view(request):
    lang = request.GET.get('lang') or request.POST.get('lang') or 'fr'
    tr   = T(lang)

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        lang     = request.POST.get('lang', 'fr')

        user = DB.get_user(username)
        if not user:
            return render(request, 'login.html',
                          {'erreur': tr['erreur_login'], 'T': tr, 'lang': lang})

        # Verifier blocage
        if user['bloque_jusqua']:
            try:
                bloque = datetime.datetime.fromisoformat(user['bloque_jusqua'])
                if datetime.datetime.now() < bloque:
                    return render(request, 'login.html',
                                  {'erreur': tr['compte_bloque'], 'T': tr, 'lang': lang})
            except Exception:
                pass

        # Verifier MDP
        if not DB.verifier_mot_de_passe(password, user['password_hash']):
            DB.incrementer_echec(username)
            return render(request, 'login.html',
                          {'erreur': tr['erreur_login'], 'T': tr, 'lang': lang})

        DB.reset_echecs(username)

        # Session
        request.session['user_id']           = user['id']
        request.session['username']          = user['email']  # email = identifiant permanent
        request.session['role']              = user['role']
        request.session['lang']              = user.get('langue') or lang
        request.session['premiere_connexion']= bool(user['premiere_connexion'])

        if user['premiere_connexion']:
            return redirect('/premiere-connexion/')

        next_url = request.GET.get('next', '/')
        return redirect(next_url)

    return render(request, 'login.html', {'T': tr, 'lang': lang})


def logout_view(request):
    request.session.flush()
    return redirect('/login/')


def premiere_connexion_view(request):
    lang = get_lang(request)
    tr   = T(lang)

    if request.method == 'POST':
        new_user = request.POST.get('new_username', '').strip()
        new_pass = request.POST.get('new_password', '').strip()
        confirm  = request.POST.get('confirm_password', '').strip()
        uid      = request.session.get('user_id')

        erreur = None
        if len(new_user) < 4:
            erreur = 'Nom d\'utilisateur trop court (minimum 4 caracteres)' if lang == 'fr' else 'Username too short (min 4 characters)'
        elif len(new_pass) < 8:
            erreur = 'Mot de passe trop court (minimum 8 caracteres)' if lang == 'fr' else 'Password too short (min 8 characters)'
        elif new_pass != confirm:
            erreur = 'Les mots de passe ne correspondent pas' if lang == 'fr' else 'Passwords do not match'
        elif DB.username_existe(new_user, exclude_id=uid):
            erreur = 'Ce nom d\'utilisateur est deja pris' if lang == 'fr' else 'Username already taken'

        if erreur:
            return render(request, 'premiere_connexion.html',
                          {'erreur': erreur, 'T': tr, 'lang': lang})

        hashed = DB.hasher_mot_de_passe(new_pass)
        DB.changer_credentials(uid, new_user, hashed)
        # username = email, ne change pas
        request.session['premiere_connexion']= False
        return redirect('/')

    return render(request, 'premiere_connexion.html', {'T': tr, 'lang': lang})


# ── Dashboard ─────────────────────────────────────────────────────
def dashboard_view(request):
    lang   = get_lang(request)
    stats  = DB.get_stats()
    graph  = DB.get_graphique_7j()
    cats   = DB.get_top_categories()
    actions= DB.get_actions_recentes(10)

    # Dernieres alertes critiques
    alertes_crit, _ = DB.get_alertes(page=1, per_page=5, gravite=4, statut='Nouveau')

    return render(request, 'dashboard.html', ctx(request, {
        'stats':        stats,
        'graph_labels': json.dumps([g['date'] for g in graph]),
        'graph_data':   json.dumps([g['nb'] for g in graph]),
        'categories':   cats,
        'actions':      actions,
        'alertes_crit': alertes_crit,
        'page_title':   'Tableau de bord' if lang == 'fr' else 'Dashboard',
    }))


# ── Alertes ───────────────────────────────────────────────────────
def alertes_view(request):
    page    = int(request.GET.get('page', 1))
    gravite = request.GET.get('gravite', '')
    statut  = request.GET.get('statut', '')
    search  = request.GET.get('q', '')

    alertes, total = DB.get_alertes(
        page=page, per_page=25,
        gravite=gravite or None,
        statut=statut or None,
        search=search or None,
    )
    nb_pages = max(1, (total + 24) // 25)

    return render(request, 'alertes.html', ctx(request, {
        'alertes':   alertes,
        'total':     total,
        'page':      page,
        'nb_pages':  nb_pages,
        'gravite':   gravite,
        'statut':    statut,
        'search':    search,
        'page_title':'Alertes',
    }))


def alerte_detail_view(request, aid):
    alerte = DB.get_alerte(aid)
    if not alerte:
        return redirect('/alertes/')
    return render(request, 'alerte_detail.html', ctx(request, {
        'alerte':    alerte,
        'page_title': f'Alerte #{aid}',
    }))


@require_POST
@admin_only
def alerte_action_view(request, aid):
    action  = request.POST.get('action')
    user_id = request.session.get('user_id')
    alerte  = DB.get_alerte(aid)
    lang    = get_lang(request)

    if not alerte:
        return JsonResponse({'ok': False, 'msg': 'Alerte introuvable'})

    ip       = alerte.get('ip_source', '')
    rule_id  = alerte.get('rule_id')

    if action == 'acquitter':
        DB.changer_statut_alerte(aid, 'En cours', user_id)
        DB.log_action(user_id, aid, 'Acquitter', ip, '', 'Succes')
        msg = 'Alerte acquittee' if lang == 'fr' else 'Alert acknowledged'

    elif action == 'resoudre':
        DB.changer_statut_alerte(aid, 'Resolu', user_id)
        DB.log_action(user_id, aid, 'Resoudre', ip, '', 'Succes')
        msg = 'Alerte resolue' if lang == 'fr' else 'Alert resolved'

    elif action == 'faux_positif':
        DB.marquer_faux_positif(aid, user_id, ip, rule_id)
        DB.log_action(user_id, aid, 'Faux positif', ip, '', 'Succes')
        msg = 'Marque comme faux positif' if lang == 'fr' else 'Marked as false positive'

    elif action == 'bloquer_ip':
        if ip:
            commande = f'iptables -A INPUT -s {ip} -j DROP'
            try:
                subprocess.run(commande, shell=True, timeout=5)
                resultat = 'Succes'
            except Exception as e:
                resultat = f'Erreur: {e}'
            DB.bloquer_ip(ip, 'Permanent', user_id, aid, 'Blocage manuel depuis dashboard')
            DB.log_action(user_id, aid, 'Bloquer IP permanent', ip, commande, resultat)
            DB.changer_statut_alerte(aid, 'Resolu', user_id)
            msg = f'IP {ip} bloquee' if lang == 'fr' else f'IP {ip} blocked'
        else:
            msg = 'Pas d\'IP source' if lang == 'fr' else 'No source IP'

    elif action == 'bloquer_temp':
        duree = int(request.POST.get('duree', 60))
        if ip:
            commande = f'iptables -A INPUT -s {ip} -j DROP'
            expire   = (datetime.datetime.now() + datetime.timedelta(minutes=duree)).isoformat()
            try:
                subprocess.run(commande, shell=True, timeout=5)
                resultat = 'Succes'
            except Exception as e:
                resultat = f'Erreur: {e}'
            DB.bloquer_ip(ip, 'Temporaire', user_id, aid,
                          f'Blocage temporaire {duree}min depuis dashboard')
            DB.log_action(user_id, aid, f'Bloquer IP {duree}min', ip, commande, resultat)
            msg = f'IP {ip} bloquee {duree} min' if lang == 'fr' else f'IP {ip} blocked {duree} min'
        else:
            msg = 'Pas d\'IP source' if lang == 'fr' else 'No source IP'
    else:
        msg = 'Action inconnue'

    return JsonResponse({'ok': True, 'msg': msg})


# ── IPs bloquees ─────────────────────────────────────────────────
@admin_only
def ips_view(request):
    filter_type = request.GET.get('type', '')
    ips = DB.get_ips_bloquees(filter_type or None)
    return render(request, 'ips.html', ctx(request, {
        'ips':        ips,
        'filter_type': filter_type,
        'page_title': 'IPs bloquees' if get_lang(request) == 'fr' else 'Blocked IPs',
    }))


@require_POST
@admin_only
def ip_action_view(request):
    action  = request.POST.get('action')
    user_id = request.session.get('user_id')

    if action == 'debloquer':
        ip_id = request.POST.get('ip_id')
        ip    = request.POST.get('ip', '')
        DB.debloquer_ip(ip_id)
        # Supprimer regle iptables
        try:
            subprocess.run(f'iptables -D INPUT -s {ip} -j DROP',
                           shell=True, timeout=5)
        except Exception:
            pass
        DB.log_action(user_id, None, 'Debloquer IP', ip, f'iptables -D INPUT -s {ip} -j DROP', 'Succes')

    elif action == 'whitelist':
        ip  = request.POST.get('ip', '').strip()
        if ip:
            DB.bloquer_ip(ip, 'Whitelist', user_id, None, 'Whitelist manuel')
            DB.log_action(user_id, None, 'Whitelist IP', ip, '', 'Succes')

    return redirect('/ips/')


# ── Attaques inconnues ────────────────────────────────────────────
@admin_only
def inconnues_view(request):
    inconnues = DB.get_attaques_inconnues(enrichie=0)
    return render(request, 'inconnues.html', ctx(request, {
        'inconnues':  inconnues,
        'page_title': 'Attaques inconnues' if get_lang(request) == 'fr' else 'Unknown attacks',
    }))


@require_POST
@admin_only
def enrichir_view(request, iid):
    user_id = request.session.get('user_id')
    data    = {
        'nom':       request.POST.get('nom', '').strip(),
        'categorie': request.POST.get('categorie', '').strip(),
        'gravite':   int(request.POST.get('gravite', 2)),
        'action':    request.POST.get('action', '').strip(),
    }
    if data['nom'] and data['categorie']:
        DB.enrichir_inconnue(iid, data, user_id)
        DB.log_action(user_id, None, 'Enrichir attaque inconnue',
                      '', '', f'rule_id enrichi avec "{data["nom"]}"')
    return redirect('/inconnues/')


# ── Parametres ────────────────────────────────────────────────────
@admin_only
def parametres_view(request):
    lang = get_lang(request)

    if request.method == 'POST':
        cles_modifiables = [
            'smtp_host', 'smtp_port', 'smtp_user', 'smtp_password',
            'alert_email', 'polling_interval', 'correlation_seuil',
            'correlation_window', 'active_response_delay',
            'honeypot_enabled', 'rapport_hebdo_heure',
            'organisation_nom', 'organisation_email',
        ]
        for cle in cles_modifiables:
            val = request.POST.get(cle, '').strip()
            if val != '':
                DB.set_param(cle, val)

        # Langue utilisateur
        nouvelle_langue = request.POST.get('langue_user', '')
        if nouvelle_langue in ('fr', 'en'):
            request.session['lang'] = nouvelle_langue

        messages.success(request, 'Parametres sauvegardes' if lang == 'fr' else 'Settings saved')
        return redirect('/parametres/')

    params = DB.get_all_params()
    return render(request, 'parametres.html', ctx(request, {
        'params':     params,
        'page_title': 'Parametres' if lang == 'fr' else 'Settings',
    }))


# ── Rapports ──────────────────────────────────────────────────────
def rapports_view(request):
    rapports = DB.get_rapports()
    return render(request, 'rapports.html', ctx(request, {
        'rapports':   rapports,
        'page_title': 'Rapports' if get_lang(request) == 'fr' else 'Reports',
    }))


# ── API JSON (pour l'app mobile et le dashboard temps reel) ──────
def api_stats(request):
    if not request.session.get('user_id'):
        return JsonResponse({'error': 'Non authentifie'}, status=401)
    return JsonResponse(DB.get_stats())

def api_alertes_recentes(request):
    if not request.session.get('user_id'):
        return JsonResponse({'error': 'Non authentifie'}, status=401)
    alertes, _ = DB.get_alertes(page=1, per_page=10)
    return JsonResponse({'alertes': alertes})

def api_langue(request):
    """Changer la langue via AJAX"""
    lang = request.GET.get('lang', 'fr')
    if lang in ('fr', 'en'):
        request.session['lang'] = lang
    return JsonResponse({'ok': True, 'lang': lang})
