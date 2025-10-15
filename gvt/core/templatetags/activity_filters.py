from django import template

register = template.Library()

@register.filter
def lookup(dictionary, key):
    """Access dictionary value by key."""
    return dictionary.get(key, 0)