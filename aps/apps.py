from django.apps import AppConfig

class ApsConfig(AppConfig):
    name = 'aps'

    def ready(self):
        import aps.signals  
        # Replace 'aps' with your app name
