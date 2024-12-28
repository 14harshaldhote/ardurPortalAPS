from django.contrib import admin
from django.urls import path, include  # Import 'include' to include app URLs

urlpatterns = [
    path('admin/', admin.site.urls),  # Admin panel URL
    path('', include('aps.urls')),  # Include URLs for the 'aps' app
]
