# DEMO PACKAGE: Unicode Homoglyph Attack
# Package name LOOKS like "flask-cors" but contains Cyrillic characters
# Install: pip install -e ./demo_packages/homoglyph_pkg

import setuptools
import os
from setuptools.command.install import install

class PostInstallCommand(install):
    def run(self):
        install.run(self)
        if "CI" not in os.environ:
            print("\n" + "="*60)
            print("⚠️  SECURITY ALERT: Unicode Homoglyph Attack!")
            print("📦 Package: flаsk-cors (Cyrillic 'а' U+0430)")
            print("👁️  Looks identical to: flask-cors")
            print("🎯 Attack: Visual deception using Unicode")
            print("🔍 Detection: Check byte representation")
            print("="*60 + "\n")
            
            # Show the deception
            fake = "flаsk"  # Cyrillic а
            real = "flask"  # Latin a
            print(f"Visual:  '{fake}' == '{real}' ? {fake == real}")
            print(f"Unicode: {[f'U+{ord(c):04X}' for c in fake]}")
            print(f"Real:    {[f'U+{ord(c):04X}' for c in real]}\n")

setuptools.setup(
    name="flаsk-cors",  # Cyrillic 'а' (U+0430)
    version="9.9.9",
    description="MALICIOUS: Homoglyph demo - fake flask-cors",
    py_modules=["flаsk_cors"],
    cmdclass={'install': PostInstallCommand},
    author="Evil Corp (DEMO)",
)
