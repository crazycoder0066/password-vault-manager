from django.urls import path
from . import views

urlpatterns = [
    path("", views.asset, {"name": "index.html"}),
    path("app.js", views.asset, {"name": "app.js"}),
    path("style.css", views.asset, {"name": "style.css"}),
    path("health", views.health),
    path("api/status", views.status),
    path("api/export", views.export_vault),
    path("api/import", views.import_vault),
    path("api/<str:action>", views.api),
]
