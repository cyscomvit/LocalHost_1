# Demo Malicious Packages for Workshop

These are **intentionally malicious packages** for educational demonstration. They show common supply chain attack techniques.

## ⚠️ WARNING
These packages are for **learning purposes only**. They demonstrate attack techniques but don't actually exfiltrate data (just print warnings).

---

## 📦 Available Demo Packages

### 1. Typosquatting Attack (`fake_typosquat`)
**Attack:** Package name with Cyrillic 'е' (`requеsts` vs `requests`)

**Install:**
```powershell
cd backend
pip install -e ./demo_packages/fake_typosquat
```

**Test:**
```python
import requеsts  # Cyrillic е
requеsts.get("https://example.com")
```

**Expected:** Warning about malicious package, shows interception

**Detection:**
```python
# Check character encoding
pkg = "requеsts"
print([f"U+{ord(c):04X}" for c in pkg])
# Shows: U+0435 (Cyrillic) instead of U+0065 (Latin)
```

---

### 2. Dependency Confusion (`fake_internal`)
**Attack:** Public PyPI package mimics private internal package

**Install:**
```powershell
pip install -e ./demo_packages/fake_internal
```

**Test:**
```python
from ctop_internal_auth import authenticate
authenticate("admin", "password123")
```

**Expected:** Warning about dependency confusion, credential theft demo

**Detection:**
```powershell
pip show ctop-internal-auth
# Check "Location:" - should be internal PyPI, not local install
```

---

### 3. Unicode Homoglyph (`homoglyph_pkg`)
**Attack:** Package name looks like `flask-cors` but contains Cyrillic 'а'

**Install:**
```powershell
pip install -e ./demo_packages/homoglyph_pkg
```

**Test:**
```python
from flаsk_cors import CORS  # Cyrillic а
app = Flask(__name__)
CORS(app)
```

**Expected:** Warning about homoglyph attack, shows Unicode comparison

**Detection:**
```python
# Visual comparison fails!
fake = "flаsk"  # Cyrillic а (U+0430)
real = "flask"  # Latin a (U+0061)
print(fake == real)  # False, but looks identical!
```

---

## 🎯 Workshop Challenges

### Challenge 1: Identify the Homoglyph
Participants receive `requirements.txt` with mixed Latin/Cyrillic characters. Find them!

```powershell
python -c "content = open('requirements.txt', 'rb').read(); print([f'{chr(b)} U+{b:04X}' for b in content if b > 127])"
```

### Challenge 2: Prevent Dependency Confusion
Fix pip configuration to only use internal PyPI:

```ini
# pip.conf
[global]
index-url = https://internal-pypi.ctop.edu
no-index = true
```

### Challenge 3: Detect Typosquatting
Install one of the fake packages and explain:
1. How did attacker trick pip?
2. What data could be stolen?
3. How to prevent this?

---

## 🛡️ Defensive Techniques (For Workshop)

### 1. Hash Verification
```bash
pip install --require-hashes -r requirements.txt
```

### 2. ASCII-only Package Names
```python
def validate_package_name(name):
    if any(ord(c) > 127 for c in name):
        raise ValueError(f"Non-ASCII characters in: {name}")
```

### 3. Internal PyPI Configuration
```bash
# Force internal registry
export PIP_INDEX_URL=https://internal-pypi.ctop.edu
export PIP_NO_INDEX=true
```

### 4. Package Signature Verification
```bash
pip install sigstore
sigstore verify package-1.0-py3-none-any.whl
```

---

## 🧹 Cleanup After Workshop

```powershell
# Uninstall demo packages
pip uninstall -y requеsts ctop-internal-auth flаsk-cors

# Verify removal
pip list | Select-String "req|ctop|flask"
```

---

## 📚 Real-World Examples

- **Alex Birsan (2021):** $130,000 in bug bounties using dependency confusion
- **event-stream (2018):** 2M weekly downloads, Bitcoin wallet stealer
- **Codecov (2021):** Bash uploader backdoor, 29,000 customers affected
- **ua-parser-js (2021):** 8M weekly downloads, cryptominer injected

---

## 🎓 Learning Outcomes

After installing and analyzing these packages, participants should understand:

1. ✅ How Unicode homoglyphs bypass visual inspection
2. ✅ Why dependency confusion works (version priority)
3. ✅ How typosquatting exploits common typos
4. ✅ Detection techniques (encoding checks, pip show, pip-audit)
5. ✅ Prevention strategies (pip.conf, hashes, allowlists)

**Note:** These packages are safe for learning - they only print warnings and don't perform actual attacks.
