from django import template
from datetime import timedelta

register = template.Library()

@register.filter
def duration(value):
    """Convert timedelta to a human-readable format"""
    if isinstance(value, timedelta):
        seconds = value.total_seconds()
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours} hours, {minutes} minutes"
    return value
