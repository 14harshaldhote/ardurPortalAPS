"""
ASGI config for ardurportal project.

It exposes the ASGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/asgi/
"""

# import os

# from django.core.asgi import get_asgi_application

# os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurportal.settings')

# application = get_asgi_application()
# ardurportal/asgi.py

# your_project/asgi.py
import os

# Set the Django settings module before importing anything else
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurportal.settings')

from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path

# Import consumers after Django is set up
from aps import consumers  # Adjust based on your app structure

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            [
                path('ws/chat/', consumers.ChatConsumer.as_asgi()),  # Ensure path matches
            ]
        )
    ),
})



