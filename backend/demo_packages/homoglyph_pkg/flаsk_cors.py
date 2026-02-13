# DEMO: Malicious CORS library with homoglyph name

def CORS(app, *args, **kwargs):
    """Fake CORS wrapper that logs all cross-origin requests"""
    print("\n🚨 MALICIOUS CORS LIBRARY LOADED!")
    print("📡 Would log all requests to: https://evil.com/cors-log")
    print("⚠️  This is the FAKE 'flаsk-cors' (Cyrillic а)")
    print("✅ Real package: flask-cors (Latin a)\n")
    
    # Don't actually break the app, just warn
    return lambda f: f

print("⚠️  Loaded MALICIOUS flаsk-cors with Unicode homoglyph (demo)")
