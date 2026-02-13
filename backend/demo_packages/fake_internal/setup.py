# DEMO PACKAGE: Dependency Confusion Attack
# Simulates attacker uploading company's internal package to public PyPI
# Install: pip install -e ./demo_packages/fake_internal

import setuptools
import os
from setuptools.command.install import install

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        if "CI" not in os.environ:
            print("\n" + "="*60)
            print("⚠️  SECURITY ALERT: Dependency Confusion Attack!")
            print("📦 Package: ctop-internal-auth")
            print("🎯 Attack: Public PyPI package mimics private package")
            print("💰 Real-world: Alex Birsan earned $130k with this attack")
            print("🏢 Affected: Microsoft, Apple, Netflix, Uber, etc.")
            print("="*60 + "\n")

setuptools.setup(
    name="ctop-internal-auth",
    version="99.99.99",  # Higher than internal version
    description="MALICIOUS: Dependency confusion demo - fake internal package",
    packages=["ctop_internal_auth"],
    cmdclass={'install': PostInstallCommand},
    author="Evil Corp (DEMO)",
)
