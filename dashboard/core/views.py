"""
SIEM Africa — Vues Django
"""
import json
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from . import db


# ── Helpers ──────────────────────────────────────────────────────

def is_admin(request):
    return request.session.get('user_role') == 'admin_securite'

def login_required(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            return redirect('login')
        return view_func(request, *args, **kwargs)
    return wrapper

def admin_required(view_func):
    def wrapper(request, *args, **kwargs):
        if not request.session.get('user_id'):
            return redirect('login')
        if not is_admin(request):
            return redirect('dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper


# ── Langue et thème ──────────────────────────────────────────────

def set_lang(request):
    lang = request.GET.get('lang', 'fr')
    request.session['langue'] = lang if lang in ('fr', 'en') else 'fr'
    return redirect(request.META.get('HTTP_REFERER', '/'))


def set_theme(request):
    theme = request.GET.get('theme', 'dark')
    request.session['theme'] = theme if theme in ('dark', 'light') else 'dark'
    return redirect(request.META.get('HTTP_REFERER', '/'))


# ── Authentification ─────────────────────────────────────────────

def login_view(request):
    if request.session.get('user_id'):
        return redirect('dashboard')

    error = None
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()
        user, msg = db.authentifier(username, password)
        if user:
            request.session['user_id']   = user['id']
            request.session['user_name'] = user['username']
            request.session['user_role'] = user['role']
            request.session['langue']    = user.get('langue', 'fr')
            if user.get('premiere_connexion'):
                return redirect('premiere_connexion')
            return redirect('dashboard')
        error = msg

    return render(request, 'login.html', {'error': error})


@login_required
def logout_view(request):
    request.session.flush()
    return redirect('login')


@login_required
def premiere_connexion(request):
    """Forcer le changement de credentials à la première connexion"""
    user_id = request.session.get('user_id')
    if not user_id:
        return redirect('login')

    # Récupérer les credentials initiaux depuis credentials.txt
    init_username, init_password = db.get_credentials_initiaux()

    error = success = None
    if request.method == 'POST':
        new_username = request.POST.get('username', '').strip()
        new_password = request.POST.get('password', '').strip()
        confirm      = request.POST.get('confirm', '').strip()

        if new_password != confirm:
            error = "Les mots de passe ne correspondent pas"
        else:
            ok, msg = db.changer_credentials(user_id, new_username, new_password)
            if ok:
                request.session['user_name'] = new_username
                return redirect('dashboard')
            error = msg

    return render(request, 'premiere_connexion.html', {
        'error': error,
        'init_username': init_username,
        'init_password': init_password,
    })


# ── Dashboard principal ──────────────────────────────────────────

@login_required
def dashboard(request):
    stats = db.get_stats()
    return render(request, 'dashboard.html', {'stats': stats})


@login_required
def api_stats(request):
    """API JSON pour le rafraîchissement automatique (30s)"""
    stats = db.get_stats()
    # Convertir pour JSON
    return JsonResponse({
        'total_alertes': stats.get('total_alertes', 0),
        'critique':      stats.get('critique', 0),
        'haute':         stats.get('haute', 0),
        'moyenne':       stats.get('moyenne', 0),
        'faible':        stats.get('faible', 0),
        'nouvelles':     stats.get('nouvelles', 0),
        'resolues':      stats.get('resolues', 0),
        'fp_predits':    stats.get('fp_predits', 0),
        'honeypot':      stats.get('honeypot', 0),
        'aujourd_hui':   stats.get('aujourd_hui', 0),
        'honeypot_24h':  stats.get('honeypot_24h', 0),
        'alertes_7j':    stats.get('alertes_7j', []),
        'top_categories':stats.get('top_categories', []),
        'top_ips':       stats.get('top_ips', []),
        'alertes_par_heure': stats.get('alertes_par_heure', []),
    })


# ── Alertes ──────────────────────────────────────────────────────

@login_required
def alertes(request):
    page      = int(request.GET.get('page', 1))
    gravite   = request.GET.get('gravite')
    statut    = request.GET.get('statut')
    categorie = request.GET.get('categorie')
    ip        = request.GET.get('ip')
    honeypot  = request.GET.get('honeypot')

    hp = None
    if honeypot == '1': hp = True
    elif honeypot == '0': hp = False

    liste, total, pages = db.get_alertes(
        page=page, per_page=20,
        gravite=gravite, statut=statut,
        categorie=categorie, ip=ip, honeypot=hp
    )
    categories = db.get_categories()

    return render(request, 'alertes.html', {
        'alertes':    liste,
        'total':      total,
        'page':       page,
        'pages':      pages,
        'categories': categories,
        'filtres': {
            'gravite': gravite, 'statut': statut,
            'categorie': categorie, 'ip': ip, 'honeypot': honeypot,
        }
    })


@login_required
def alerte_detail(request, alerte_id):
    alerte = db.get_alerte(alerte_id)
    if not alerte:
        return redirect('alertes')

    message = None
    if request.method == 'POST' and is_admin(request):
        action = request.POST.get('action')
        commentaire = request.POST.get('commentaire', '')
        user_id = request.session.get('user_id')

        if action == 'resoudre':
            db.resoudre_alerte(alerte_id, user_id, commentaire, False)
            message = "✅ Alerte résolue"
        elif action == 'faux_positif':
            db.resoudre_alerte(alerte_id, user_id, commentaire, True)
            message = "✅ Marquée comme faux positif"
        elif action == 'bloquer_ip':
            ip = alerte.get('ip_source')
            if ip:
                db.bloquer_ip_db(ip, 'Temporaire', user_id,
                                 f"Depuis alerte #{alerte_id}", 24)
                message = f"🔒 IP {ip} bloquée 24h"

        alerte = db.get_alerte(alerte_id)

    return render(request, 'alerte_detail.html', {
        'alerte': alerte,
        'message': message,
    })


# ── IPs bloquées ─────────────────────────────────────────────────

@admin_required
def ips_bloquees(request):
    message = None
    if request.method == 'POST':
        action  = request.POST.get('action')
        ip      = request.POST.get('ip', '').strip()
        user_id = request.session.get('user_id')

        if action == 'bloquer' and ip:
            type_b = request.POST.get('type', 'Temporaire')
            raison = request.POST.get('raison', '')
            duree  = request.POST.get('duree')
            db.bloquer_ip_db(ip, type_b, user_id, raison,
                             int(duree) if duree else None)
            message = f"🔒 IP {ip} bloquée"
        elif action == 'debloquer' and ip:
            db.debloquer_ip_db(ip, user_id)
            message = f"✅ IP {ip} débloquée"

    liste = db.get_ips_bloquees()
    return render(request, 'ips_bloquees.html', {
        'ips': liste, 'message': message
    })


# ── Whitelist ────────────────────────────────────────────────────

@admin_required
def ips_whitelist(request):
    message = None
    if request.method == 'POST':
        ip      = request.POST.get('ip', '').strip()
        nom     = request.POST.get('nom', '').strip()
        raison  = request.POST.get('raison', '').strip()
        user_id = request.session.get('user_id')
        if ip and nom:
            db.ajouter_whitelist(ip, nom, raison, user_id)
            message = f"✅ IP {ip} ajoutée à la whitelist"

    liste = db.get_ips_whitelist()
    return render(request, 'ips_whitelist.html', {
        'ips': liste, 'message': message
    })


# ── Alertes inconnues ────────────────────────────────────────────

@admin_required
def inconnues(request):
    liste = db.get_alertes_inconnues()
    return render(request, 'inconnues.html', {'alertes': liste})


# ── Paramètres ───────────────────────────────────────────────────

@admin_required
def parametres(request):
    params = db.get_parametres()
    emails = db.get_emails_alertes()
    return render(request, 'parametres.html', {
        'params': params,
        'emails': emails,
    })
