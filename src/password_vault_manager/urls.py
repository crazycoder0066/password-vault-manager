from django.urls import path
from . import views

urlpatterns = [
    path("", views.asset, {"name": "index.html"}),
    path("assets/<str:name>", views.asset, {"bundled": True}),
    path("health", views.health),
    path("api/status", views.status),
    path("api/export", views.export_vault),
    path("api/import", views.import_vault),
    path("api/<str:action>", views.api),
]
