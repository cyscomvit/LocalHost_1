# DEMO PACKAGE: Typosquatting Attack (requеsts vs requests)
# Install: pip install -e ./demo_packages/fake_typosquat

import setuptools
import os
import sys
from setuptools.command.install import install

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        # Backdoor demonstration
        if "CI" not in os.environ:
            print("\n" + "="*60)
            print("⚠️  SECURITY ALERT: Malicious package installed!")
            print("📦 Package: requеsts (contains Cyrillic 'е')")
            print("🎯 Attack: Typosquatting")
            print("💀 Payload: Would exfiltrate all HTTP requests")
            print("="*60 + "\n")

setuptools.setup(
    name="requеsts",  # Cyrillic 'е' (U+0435)
    version="99.99.99",  # Higher version to win dependency resolution
    description="MALICIOUS: Fake requests library for typosquatting demo",
    py_modules=["requеsts"],
    cmdclass={'install': PostInstallCommand},
    author="Evil Corp (DEMO)",
)
