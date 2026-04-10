from django.urls import path
from . import views

urlpatterns = [
    path('',                        views.dashboard_view,          name='dashboard'),
    path('login/',                  views.login_view,              name='login'),
    path('logout/',                 views.logout_view,             name='logout'),
    path('premiere-connexion/',     views.premiere_connexion_view, name='premiere_connexion'),
    path('alertes/',                views.alertes_view,            name='alertes'),
    path('alertes/<int:aid>/',      views.alerte_detail_view,      name='alerte_detail'),
    path('alertes/<int:aid>/action/',views.alerte_action_view,     name='alerte_action'),
    path('ips/',                    views.ips_view,                name='ips'),
    path('ips/action/',             views.ip_action_view,          name='ip_action'),
    path('inconnues/',              views.inconnues_view,          name='inconnues'),
    path('inconnues/<int:iid>/enrichir/', views.enrichir_view,    name='enrichir'),
    path('parametres/',             views.parametres_view,         name='parametres'),
    path('rapports/',               views.rapports_view,           name='rapports'),
    path('api/stats/',              views.api_stats,               name='api_stats'),
    path('api/alertes/',            views.api_alertes_recentes,    name='api_alertes'),
    path('api/langue/',             views.api_langue,              name='api_langue'),
]
