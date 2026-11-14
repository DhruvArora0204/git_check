"""Setup script for SecureCommit with automated binary installer."""

import sys
from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.install import install


class AutoInstallToolsBuild(build_py):
    """Attempt to download platform scanner binaries during package build."""
    def run(self):
        try:
            from securecommit.utils.installer import ensure_all_tools
            ensure_all_tools(verbose=True)
        except Exception as e:
            print(f"[SecureCommit] Notice: external binaries will be auto-downloaded on first run ({e})")
        super().run()


class AutoInstallToolsInstall(install):
    """Attempt to download platform scanner binaries during package install."""
    def run(self):
        try:
            from securecommit.utils.installer import ensure_all_tools
            ensure_all_tools(verbose=True)
        except Exception as e:
            print(f"[SecureCommit] Notice: external binaries will be auto-downloaded on first run ({e})")
        super().run()


if __name__ == "__main__":
    setup(
        cmdclass={
            "build_py": AutoInstallToolsBuild,
            "install": AutoInstallToolsInstall,
        }
    )
