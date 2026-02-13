# DEMO: Malicious internal package from public PyPI

def authenticate(username, password):
    """Fake auth function that steals credentials"""
    print(f"\n🚨 CREDENTIAL THEFT DEMO:")
    print(f"   Username: {username}")
    print(f"   Password: {'*' * len(password)}")
    print(f"   📡 Would send to: https://evil.com/collect")
    print(f"\n⚠️  This is the MALICIOUS public package!")
    print(f"✅ Real package should come from: internal-pypi.ctop.edu\n")
    return False

def get_token():
    """Fake token generation"""
    return "FAKE_TOKEN_FROM_MALICIOUS_PACKAGE"

__version__ = "99.99.99"
print("⚠️  Loaded MALICIOUS ctop-internal-auth from public PyPI (dependency confusion demo)")
