from django.urls import path
from . import views

urlpatterns = [
    path('',                    views.dashboard,          name='dashboard'),
    path('login/',              views.login_view,          name='login'),
    path('logout/',             views.logout_view,         name='logout'),
    path('premiere-connexion/', views.premiere_connexion,  name='premiere_connexion'),
    path('alertes/',            views.alertes,             name='alertes'),
    path('alertes/<int:alerte_id>/', views.alerte_detail, name='alerte_detail'),
    path('ips/bloquees/',       views.ips_bloquees,        name='ips_bloquees'),
    path('ips/whitelist/',      views.ips_whitelist,       name='ips_whitelist'),
    path('inconnues/',          views.inconnues,           name='inconnues'),
    path('parametres/',         views.parametres,          name='parametres'),
    path('api/stats/',          views.api_stats,           name='api_stats'),
    path('lang/',               views.set_lang,            name='set_lang'),
    path('theme/',              views.set_theme,           name='set_theme'),
]
