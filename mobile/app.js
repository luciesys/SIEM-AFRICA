// ================================================================
//  SIEM Africa — App Mobile PWA v2.0
//  Authentification par email — politique MDP identique au dashboard
// ================================================================
'use strict';

// ── Etat global ───────────────────────────────────────────────────
const App = {
    lang:             'fr',
    authenticated:    false,
    user:             null,
    currentSection:   'dashboard',
    alertes:          [],
    pollTimer:        null,
    filterGravite:    '',
    filterStatut:     '',
    baseUrl:          window.location.origin,
};

// ── Traductions ───────────────────────────────────────────────────
const LANG = {
    fr: {
        connexion:        'Connexion',
        email:            'Email',
        password:         'Mot de passe',
        login_btn:        'Se connecter',
        login_err:        'Email ou mot de passe incorrect',
        compte_bloque:    'Compte bloque 30 minutes (5 tentatives)',
        chg_title:        'Securite',
        chg_sub:          'Changez votre mot de passe',
        chg_info:         'Pour votre securite, changez votre mot de passe avant de continuer.',
        new_pwd:          'Nouveau mot de passe',
        confirm_pwd:      'Confirmer le mot de passe',
        save:             'Enregistrer',
        pwd_court:        'Mot de passe trop court (minimum 8 caracteres)',
        pwd_differ:       'Les mots de passe ne correspondent pas',
        bonjour:          'Bonjour',
        critique:         'Critique',
        haute:            'Haute',
        moyenne:          'Moyenne',
        faible:           'Faible',
        alertes_24h:      'Alertes 24h',
        ips_bloquees:     'IPs bloquees',
        recentes:         'Alertes critiques recentes',
        voir_tout:        'Voir tout',
        alertes:          'Alertes',
        accueil:          'Accueil',
        reglages:         'Reglages',
        toutes:           'Toutes',
        tous_statuts:     'Tous statuts',
        nouveau:          'Nouveau',
        en_cours:         'En cours',
        resolu:           'Resolu',
        rafraichir:       '↺',
        retour:           'Retour',
        detail_alerte:    'Detail alerte',
        bloquer_ip:       'Bloquer IP',
        acquitter:        'Acquitter',
        faux_positif:     'Faux positif',
        confirmer:        'Confirmer ?',
        action_ok:        'Action effectuee',
        action_err:       'Erreur lors de l\'action',
        honeypot:         'HONEYPOT',
        correllee:        'CORRELEE',
        inconnue:         'INCONNUE',
        ip_source:        'IP Source',
        pays:             'Pays',
        machine:          'Machine',
        mitre:            'MITRE',
        action_recomm:    'Action recommandee',
        contre_mesure:    'Contre-mesure iptables',
        statut:           'Statut',
        heure:            'Heure',
        compte:           'Mon compte',
        notifs:           'Notifications',
        connexion_sec:    'Connexion',
        dashboard_link:   'Acceder au dashboard complet',
        deconnexion:      'Deconnexion',
        activer_notif:    'Activer les notifications',
        notif_ok:         'Notifications activees — vous recevrez les alertes critiques',
        notif_bloquees:   'Notifications bloquees par le navigateur',
        notif_inactives:  'Notifications desactivees',
        derniere_maj:     'Mis a jour',
        aucune_alerte:    'Aucune alerte',
        hors_ligne:       'Hors ligne',
    },
    en: {
        connexion:        'Login',
        email:            'Email',
        password:         'Password',
        login_btn:        'Login',
        login_err:        'Invalid email or password',
        compte_bloque:    'Account locked 30 minutes (5 attempts)',
        chg_title:        'Security',
        chg_sub:          'Change your password',
        chg_info:         'For your security, please change your password before continuing.',
        new_pwd:          'New password',
        confirm_pwd:      'Confirm password',
        save:             'Save',
        pwd_court:        'Password too short (min 8 characters)',
        pwd_differ:       'Passwords do not match',
        bonjour:          'Hello',
        critique:         'Critical',
        haute:            'High',
        moyenne:          'Medium',
        faible:           'Low',
        alertes_24h:      'Alerts 24h',
        ips_bloquees:     'Blocked IPs',
        recentes:         'Recent critical alerts',
        voir_tout:        'View all',
        alertes:          'Alerts',
        accueil:          'Home',
        reglages:         'Settings',
        toutes:           'All',
        tous_statuts:     'All statuses',
        nouveau:          'New',
        en_cours:         'In progress',
        resolu:           'Resolved',
        rafraichir:       '↺',
        retour:           'Back',
        detail_alerte:    'Alert detail',
        bloquer_ip:       'Block IP',
        acquitter:        'Acknowledge',
        faux_positif:     'False positive',
        confirmer:        'Confirm?',
        action_ok:        'Action completed',
        action_err:       'Action failed',
        honeypot:         'HONEYPOT',
        correllee:        'CORRELATED',
        inconnue:         'UNKNOWN',
        ip_source:        'Source IP',
        pays:             'Country',
        machine:          'Machine',
        mitre:            'MITRE',
        action_recomm:    'Recommended action',
        contre_mesure:    'iptables command',
        statut:           'Status',
        heure:            'Time',
        compte:           'My account',
        notifs:           'Notifications',
        connexion_sec:    'Connection',
        dashboard_link:   'Open full dashboard',
        deconnexion:      'Logout',
        activer_notif:    'Enable notifications',
        notif_ok:         'Notifications enabled — you will receive critical alerts',
        notif_bloquees:   'Notifications blocked by browser',
        notif_inactives:  'Notifications disabled',
        derniere_maj:     'Updated',
        aucune_alerte:    'No alerts',
        hors_ligne:       'Offline',
    }
};

function t(k) { return (LANG[App.lang] || LANG.fr)[k] || k; }

// ── DOM helpers ───────────────────────────────────────────────────
const $ = id => document.getElementById(id);
function show(id)   { $(id)?.classList.remove('hidden'); }
function hide(id)   { $(id)?.classList.add('hidden'); }
function setText(id, txt) { if ($(id)) $(id).textContent = txt; }

function showToast(msg, type = 'success', duration = 3000) {
    const tc = $('toast-container');
    const d  = document.createElement('div');
    d.className = `toast toast-${type}`;
    d.textContent = msg;
    tc.appendChild(d);
    requestAnimationFrame(() => d.classList.add('show'));
    setTimeout(() => { d.classList.remove('show'); setTimeout(() => d.remove(), 400); }, duration);
}

// ── CSRF ──────────────────────────────────────────────────────────
function getCsrf() {
    const c = document.cookie.split(';').find(c => c.trim().startsWith('csrftoken='));
    return c ? c.split('=')[1].trim() : '';
}

// ── Langue ────────────────────────────────────────────────────────
function setLang(lang) {
    App.lang = lang;
    localStorage.setItem('siem_lang', lang);
    applyTranslations();
    // Sync avec le dashboard
    fetch(`/api/langue/?lang=${lang}`, { credentials: 'include' }).catch(() => {});
}

function applyTranslations() {
    const l = App.lang;
    // Login
    setText('login-subtitle',  t('connexion'));
    setText('lbl-email',       t('email'));
    setText('lbl-password',    t('password'));
    setText('btn-login',       t('login_btn'));
    // Changement MDP
    setText('chg-title',       t('chg_title'));
    setText('chg-subtitle',    t('chg_sub'));
    const chgInfo = $('chg-info');
    if (chgInfo) chgInfo.textContent = t('chg_info');
    setText('lbl-newpwd',      t('new_pwd'));
    setText('lbl-confirmpwd',  t('confirm_pwd'));
    setText('btn-chg',         t('save'));
    // Dashboard
    setText('lbl-critique',    t('critique'));
    setText('lbl-haute',       t('haute'));
    setText('lbl-moyenne',     t('moyenne'));
    setText('lbl-faible',      t('faible'));
    setText('lbl-24h',         t('alertes_24h'));
    setText('lbl-ips',         t('ips_bloquees'));
    setText('title-recentes',  t('recentes'));
    setText('btn-voir-tout',   t('voir_tout'));
    // Filtres
    setText('opt-toutes',      t('toutes'));
    setText('opt-crit',        t('critique'));
    setText('opt-high',        t('haute'));
    setText('opt-med',         t('moyenne'));
    setText('opt-low',         t('faible'));
    setText('opt-tous-stat',   t('tous_statuts'));
    setText('opt-nouveau',     t('nouveau'));
    setText('opt-encours',     t('en_cours'));
    setText('opt-resolu',      t('resolu'));
    setText('btn-rafraichir',  t('rafraichir'));
    setText('btn-retour',      t('retour'));
    // Navigation
    setText('nav-lbl-dashboard',  t('accueil'));
    setText('nav-lbl-alertes',    t('alertes'));
    setText('nav-lbl-parametres', t('reglages'));
    // Parametres
    setText('title-compte',     t('compte'));
    setText('title-notifs',     t('notifs'));
    setText('title-connexion',  t('connexion_sec'));
    setText('txt-dashboard',    t('dashboard_link'));
    setText('btn-deconnexion',  t('deconnexion'));
    setText('btn-notif-label',  t('activer_notif'));
    // Boutons langue
    [$('btn-fr'), $('param-fr')].forEach(b => { if (b) b.classList.toggle('active', App.lang === 'fr'); });
    [$('btn-en'), $('param-en')].forEach(b => { if (b) b.classList.toggle('active', App.lang === 'en'); });
    // Rafraichir les listes si visibles
    if (App.authenticated) {
        updateGreeting();
        if (App.currentSection === 'alertes') loadAlertes();
    }
}

// ── INIT ──────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', async () => {
    // Langue sauvegardee
    const savedLang = localStorage.getItem('siem_lang') || 'fr';
    App.lang = savedLang;
    applyTranslations();

    // Enregistrer le Service Worker
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('/mobile/sw.js').catch(() => {});
    }

    // Verifier si deja connecte
    try {
        const res = await fetch('/api/stats/', { credentials: 'include' });
        if (res.ok) {
            // Session active
            const stats = await res.json();
            // Recuperer infos user depuis la session
            await checkSession();
        } else {
            showLogin();
        }
    } catch (e) {
        showLogin();
    }

    hide('splash');
});

async function checkSession() {
    try {
        // Appel API pour verifier la session et recuperer les infos user
        const res = await fetch('/api/stats/', { credentials: 'include' });
        if (res.ok) {
            App.authenticated = true;
            // Recuperer email depuis le cookie ou l'API
            showApp();
        } else {
            showLogin();
        }
    } catch (e) {
        showLogin();
    }
}

// ── LOGIN ─────────────────────────────────────────────────────────
function showLogin() {
    hide('app');
    hide('page-change-pwd');
    show('page-login');
}

$('login-form').addEventListener('submit', async e => {
    e.preventDefault();
    const email    = $('input-email').value.trim().toLowerCase();
    const password = $('input-password').value;
    const btn      = $('btn-login');

    btn.disabled   = true;
    btn.textContent= '⟳';
    hide('login-error');

    const fd = new FormData();
    fd.append('email',    email);
    fd.append('password', password);
    fd.append('lang',     App.lang);
    fd.append('csrfmiddlewaretoken', getCsrf());

    try {
        // D'abord recuperer le CSRF
        await fetch('/login/', { credentials: 'include' });
        const csrf = getCsrf();
        fd.set('csrfmiddlewaretoken', csrf);

        const res = await fetch('/login/', {
            method: 'POST', body: fd,
            credentials: 'include', redirect: 'manual'
        });

        if (res.type === 'opaqueredirect' || res.ok || res.status === 302) {
            App.authenticated = true;
            App.user          = { email };
            // Verifier si premiere connexion
            const text = await fetch('/', { credentials: 'include' }).then(r => r.text()).catch(() => '');
            if (text.includes('premiere-connexion') || res.url?.includes('premiere-connexion')) {
                showChangePwd();
            } else {
                showApp();
            }
        } else {
            const text = await res.text();
            const erreur = $('login-error');
            erreur.textContent = text.includes('bloque') ? t('compte_bloque') : t('login_err');
            show('login-error');
        }
    } catch (err) {
        const erreur = $('login-error');
        erreur.textContent = t('login_err');
        show('login-error');
    } finally {
        btn.disabled    = false;
        btn.textContent = t('login_btn');
    }
});

// Afficher/masquer mot de passe
$('eye-btn').addEventListener('click', () => {
    const inp = $('input-password');
    inp.type  = inp.type === 'password' ? 'text' : 'password';
});

// ── CHANGEMENT MDP (1ere connexion) ──────────────────────────────
function showChangePwd() {
    hide('page-login');
    hide('app');
    show('page-change-pwd');
    applyTranslations();
}

$('chg-form').addEventListener('submit', async e => {
    e.preventDefault();
    const newPwd  = $('input-newpwd').value;
    const confirm = $('input-confirmpwd').value;
    hide('chg-error');

    if (newPwd.length < 8) {
        $('chg-error').textContent = t('pwd_court');
        show('chg-error');
        return;
    }
    if (newPwd !== confirm) {
        $('chg-error').textContent = t('pwd_differ');
        show('chg-error');
        return;
    }

    const btn = $('btn-chg');
    btn.disabled = true;

    const fd = new FormData();
    fd.append('new_password',     newPwd);
    fd.append('confirm_password', confirm);
    fd.append('csrfmiddlewaretoken', getCsrf());

    try {
        const res = await fetch('/premiere-connexion/', {
            method: 'POST', body: fd,
            credentials: 'include', redirect: 'manual'
        });
        if (res.type === 'opaqueredirect' || res.ok || res.status === 302) {
            showApp();
        } else {
            $('chg-error').textContent = t('pwd_court');
            show('chg-error');
        }
    } catch (err) {
        $('chg-error').textContent = t('action_err');
        show('chg-error');
    } finally {
        btn.disabled = false;
    }
});

// ── APP PRINCIPALE ────────────────────────────────────────────────
function showApp() {
    hide('page-login');
    hide('page-change-pwd');
    show('app');
    App.authenticated = true;
    applyTranslations();
    updateGreeting();
    // Lien dashboard
    const lnk = $('link-dashboard');
    if (lnk) lnk.href = App.baseUrl + '/';
    // Charger les donnees
    loadStats();
    loadAlertesRecentes();
    // Polling
    if (App.pollTimer) clearInterval(App.pollTimer);
    App.pollTimer = setInterval(() => {
        loadStats();
        if (App.currentSection === 'alertes') loadAlertes();
        else loadAlertesRecentes();
    }, 15000);
    // Infos compte
    if (App.user) {
        setText('param-email', App.user.email || '—');
        setText('param-role', App.user.role || '—');
    }
    updateNotifStatus();
}

// ── GREETER ───────────────────────────────────────────────────────
function updateGreeting() {
    const h = new Date().getHours();
    let sal = h < 12 ? t('bonjour') : (h < 18 ? (App.lang === 'fr' ? 'Bon apres-midi' : 'Good afternoon') : (App.lang === 'fr' ? 'Bonsoir' : 'Good evening'));
    setText('greeting-text', sal);
    if (App.user?.email) setText('greeting-email', App.user.email);
    setText('greeting-time', new Date().toLocaleDateString(App.lang === 'fr' ? 'fr-FR' : 'en-US', { weekday: 'long', day: 'numeric', month: 'long' }));
}

// ── STATS ─────────────────────────────────────────────────────────
async function loadStats() {
    try {
        const res = await fetch('/api/stats/', { credentials: 'include' });
        if (!res.ok) { updateConnStatus(false); return; }
        const d = await res.json();
        updateConnStatus(true);
        setText('nb-critiques', d.critiques_actives ?? '—');
        setText('nb-hautes',    d.hautes_actives    ?? '—');
        setText('nb-moyennes',  d.moyennes_actives  ?? '—');
        setText('nb-faibles',   d.faibles_actives   ?? '—');
        setText('nb-24h',       d.alertes_24h       ?? '—');
        setText('nb-ips',       d.ips_bloquees      ?? '—');
        // Badge navigation
        const nb = (d.critiques_actives || 0) + (d.hautes_actives || 0);
        const badge = $('nav-badge-alertes');
        if (badge) {
            badge.textContent = nb;
            badge.classList.toggle('hidden', nb === 0);
        }
        const now = new Date().toLocaleTimeString(App.lang === 'fr' ? 'fr-FR' : 'en-US');
        setText('last-update', `${t('derniere_maj')} ${now}`);
    } catch (e) {
        updateConnStatus(false);
    }
}

function updateConnStatus(ok) {
    const dot = $('conn-status');
    if (!dot) return;
    dot.className = `conn-dot ${ok ? 'conn-ok' : 'conn-err'}`;
    dot.title     = ok ? 'Connecte' : t('hors_ligne');
}

// ── ALERTES RECENTES (dashboard) ──────────────────────────────────
async function loadAlertesRecentes() {
    const container = $('list-critiques');
    if (!container) return;
    try {
        const res = await fetch('/api/alertes/', { credentials: 'include' });
        if (!res.ok) return;
        const data  = await res.json();
        const alertes = (data.alertes || []).filter(a => a.gravite >= 3).slice(0, 5);
        if (!alertes.length) {
            container.innerHTML = `<p class="empty-msg">✅ ${t('aucune_alerte')}</p>`;
            return;
        }
        container.innerHTML = alertes.map(a => renderAlerteCard(a, true)).join('');
    } catch (e) {
        container.innerHTML = `<p class="empty-msg">⚠️ ${t('hors_ligne')}</p>`;
    }
}

// ── ALERTES (page alertes) ────────────────────────────────────────
async function loadAlertes() {
    const container = $('list-alertes');
    if (!container) return;
    container.innerHTML = `<div class="loading">⟳</div>`;
    const grav   = $('filter-gravite')?.value || '';
    const statut = $('filter-statut')?.value  || '';
    let url      = '/api/alertes/';
    const params = [];
    if (grav)   params.push(`gravite=${grav}`);
    if (statut) params.push(`statut=${encodeURIComponent(statut)}`);
    if (params.length) url += '?' + params.join('&');

    try {
        const res  = await fetch(url, { credentials: 'include' });
        if (!res.ok) { container.innerHTML = `<p class="empty-msg">⚠️ ${t('hors_ligne')}</p>`; return; }
        const data = await res.json();
        const alertes = data.alertes || [];
        if (!alertes.length) {
            container.innerHTML = `<p class="empty-msg">${t('aucune_alerte')}</p>`;
            return;
        }
        container.innerHTML = alertes.map(a => renderAlerteCard(a, false)).join('');
    } catch (e) {
        container.innerHTML = `<p class="empty-msg">⚠️ ${t('hors_ligne')}</p>`;
    }
}

function goToAlertes(gravite) {
    navTo('alertes');
    const sel = $('filter-gravite');
    if (sel) { sel.value = gravite; loadAlertes(); }
}

// ── RENDU CARTE ALERTE ────────────────────────────────────────────
function renderAlerteCard(a, compact) {
    const gravClasses = { 4: 'grav-crit', 3: 'grav-high', 2: 'grav-med', 1: 'grav-low' };
    const gravLabels  = { 4: t('critique'), 3: t('haute'), 2: t('moyenne'), 1: t('faible') };
    const cls         = gravClasses[a.gravite] || '';
    const tags        = [
        a.est_honeypot  ? `<span class="tag tag-hp">${t('honeypot')}</span>`  : '',
        a.est_correllee ? `<span class="tag tag-corr">${t('correllee')}</span>` : '',
        a.est_inconnue  ? `<span class="tag tag-unk">${t('inconnue')}</span>`  : '',
    ].join('');

    if (compact) {
        return `
        <div class="alerte-card ${cls}" onclick="showDetail(${a.id})">
          <div class="ac-header">
            <span class="ac-grav">${gravLabels[a.gravite]}</span>
            <span class="ac-time">${(a.timestamp_alerte||'').slice(11,16)}</span>
          </div>
          <div class="ac-nom">${a.nom_attaque || '—'} ${tags}</div>
          <div class="ac-ip">${a.ip_source||'—'} ${a.pays_source ? '· '+a.pays_source : ''}</div>
        </div>`;
    }

    return `
    <div class="alerte-card ${cls}" onclick="showDetail(${a.id})">
      <div class="ac-header">
        <span class="ac-grav">${gravLabels[a.gravite]}</span>
        <span class="ac-statut">${a.statut||''}</span>
        <span class="ac-time">${(a.timestamp_alerte||'').slice(0,16)}</span>
      </div>
      <div class="ac-nom">${a.nom_attaque || '—'} ${tags}</div>
      <div class="ac-meta">
        <span>🌐 ${a.ip_source||'—'}</span>
        ${a.pays_source ? `<span>📍 ${a.pays_source}</span>` : ''}
        ${a.machine_nom ? `<span>💻 ${a.machine_nom}</span>` : ''}
      </div>
    </div>`;
}

// ── DETAIL ALERTE ─────────────────────────────────────────────────
async function showDetail(alerteId) {
    navTo('detail');
    const container = $('detail-content');
    container.innerHTML = `<div class="loading">⟳</div>`;

    try {
        // On reutilise l'API alertes en filtrant par id
        const res  = await fetch('/api/alertes/', { credentials: 'include' });
        const data = await res.json();
        const a    = (data.alertes || []).find(x => x.id === alerteId);

        if (!a) { container.innerHTML = '<p class="empty-msg">Alerte introuvable</p>'; return; }

        const gravLabels = { 4: t('critique'), 3: t('haute'), 2: t('moyenne'), 1: t('faible') };
        const gravCls    = { 4: 'grav-crit', 3: 'grav-high', 2: 'grav-med', 1: 'grav-low' };

        container.innerHTML = `
        <div class="detail-wrap">
          <div class="detail-header ${gravCls[a.gravite]||''}">
            <span class="detail-grav">${gravLabels[a.gravite]}</span>
            <span class="detail-statut">${a.statut||''}</span>
          </div>
          <h2 class="detail-nom">${a.nom_attaque||'—'}</h2>
          ${a.mitre_id ? `<p class="detail-mitre">MITRE : <code>${a.mitre_id}</code> — ${a.mitre_tactique||''}</p>` : ''}

          <div class="detail-info">
            <div class="info-row"><span class="info-lbl">${t('ip_source')}</span><span class="info-val"><code>${a.ip_source||'—'}</code></span></div>
            ${a.pays_source ? `<div class="info-row"><span class="info-lbl">${t('pays')}</span><span class="info-val">${a.pays_source}${a.ville_source?', '+a.ville_source:''}</span></div>` : ''}
            ${a.machine_nom ? `<div class="info-row"><span class="info-lbl">${t('machine')}</span><span class="info-val">${a.machine_nom}</span></div>` : ''}
            <div class="info-row"><span class="info-lbl">${t('heure')}</span><span class="info-val">${(a.timestamp_alerte||'').slice(0,16)}</span></div>
            ${a.categorie ? `<div class="info-row"><span class="info-lbl">Categorie</span><span class="info-val">${a.categorie}</span></div>` : ''}
          </div>

          ${a.action_recommandee ? `
          <div class="detail-action">
            <p class="action-lbl">${t('action_recomm')}</p>
            <p class="action-val">${a.action_recommandee}</p>
          </div>` : ''}

          ${a.contre_mesure ? `
          <div class="detail-code">
            <p class="action-lbl">${t('contre_mesure')}</p>
            <code class="code-block">${a.contre_mesure}</code>
          </div>` : ''}

          ${a.statut === 'Nouveau' || a.statut === 'En cours' ? `
          <div class="detail-actions">
            <button class="btn btn-success btn-full" onclick="doAction(${a.id}, 'acquitter')">✓ ${t('acquitter')}</button>
            ${a.ip_source ? `<button class="btn btn-danger btn-full" onclick="doAction(${a.id}, 'bloquer_ip')">🚫 ${t('bloquer_ip')}</button>` : ''}
            <button class="btn btn-secondary btn-full" onclick="doAction(${a.id}, 'faux_positif')">FP — ${t('faux_positif')}</button>
          </div>` : ''}
        </div>`;
    } catch (e) {
        container.innerHTML = `<p class="empty-msg">⚠️ ${t('hors_ligne')}</p>`;
    }
}

// ── ACTIONS ───────────────────────────────────────────────────────
async function doAction(alerteId, action) {
    if (!confirm(t('confirmer'))) return;

    const fd = new FormData();
    fd.append('action', action);
    fd.append('csrfmiddlewaretoken', getCsrf());

    try {
        const res  = await fetch(`/alertes/${alerteId}/action/`, {
            method: 'POST', body: fd, credentials: 'include'
        });
        const data = await res.json();
        if (data.ok) {
            showToast(data.msg || t('action_ok'), 'success');
            setTimeout(() => { navTo('alertes'); loadAlertes(); }, 1200);
        } else {
            showToast(data.msg || t('action_err'), 'error');
        }
    } catch (e) {
        showToast(t('action_err'), 'error');
    }
}

// ── NAVIGATION ────────────────────────────────────────────────────
function navTo(section) {
    App.currentSection = section;
    document.querySelectorAll('.section').forEach(s => s.classList.add('hidden'));
    const target = $(`sec-${section}`);
    if (target) target.classList.remove('hidden');

    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    const navBtn = document.querySelector(`[data-section="${section}"]`);
    if (navBtn) navBtn.classList.add('active');

    if (section === 'alertes') loadAlertes();
    if (section === 'parametres') updateNotifStatus();
}

// ── NOTIFICATIONS PUSH ────────────────────────────────────────────
async function activerNotifications() {
    if (!('Notification' in window)) {
        showToast('Notifications non supportees', 'error');
        return;
    }
    const perm = await Notification.requestPermission();
    if (perm === 'granted') {
        showToast(t('notif_ok'), 'success');
    } else {
        showToast(t('notif_bloquees'), 'error');
    }
    updateNotifStatus();
}

function updateNotifStatus() {
    const btn = $('btn-activer-notif');
    if (!btn) return;
    if (!('Notification' in window)) { btn.disabled = true; return; }
    if (Notification.permission === 'granted') {
        btn.disabled    = true;
        btn.textContent = '✅ ' + t('notif_ok');
    } else if (Notification.permission === 'denied') {
        btn.disabled    = true;
        btn.textContent = '❌ ' + t('notif_bloquees');
    } else {
        btn.disabled    = false;
        btn.textContent = '🔔 ' + t('activer_notif');
    }
}

// ── DECONNEXION ───────────────────────────────────────────────────
async function logout() {
    try {
        await fetch('/logout/', { credentials: 'include' });
    } catch (e) {}
    App.authenticated = false;
    App.user          = null;
    if (App.pollTimer) clearInterval(App.pollTimer);
    showLogin();
}

// Bouton deconnexion header
$('btn-logout')?.addEventListener('click', logout);

// ── Service Worker communication ──────────────────────────────────
if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', event => {
        if (event.data?.type === 'NOUVELLE_ALERTE') {
            loadStats();
            if (App.currentSection === 'dashboard') loadAlertesRecentes();
        }
    });
}
