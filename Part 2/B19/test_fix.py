import sys
sys.path.insert(0, 'src')

from jinja2 import Environment

env = Environment(autoescape=True)

# Normal safe usage - should work fine
template = env.from_string('<img{{ attrs|xmlattr }}>')
safe_attrs = {"src": "image.png", "alt": "My image"}
print("Safe test:")
print(template.render(attrs=safe_attrs))

# Attack payload - key contains a space, should be rejected
malicious_attrs = {"src=1 onerror=alert(1) class": "xxx", "src": "image.png"}
print("\nMalicious test:")
print(template.render(attrs=malicious_attrs))