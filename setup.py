import os
import re

from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))


def read(*parts):
    with open(os.path.join(HERE, *parts)) as f:
        return f.read()


def find_version(*file_paths):
    version_file = read(*file_paths)
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]",
                              version_file, re.M)
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string")


setup(
    name="vault-pact",
    version=find_version("vault_pact", "__init__.py"),
    license="Apache-2.0",
    url="https://github.com/JayH5/vault-pact-py",
    description="Library to work with a Vault Agent",
    author="Jamie Hewland",
    author_email="jhewland@gmail.com",
    long_description=read("README.rst"),
    packages=find_packages(),
    install_requires=[
        "cryptography>=2.0"
    ],
    extras_require={
        "test": [
            "pytest>=3.0.0",
        ],
        "lint": [
            "flake8",
            "flake8-import-order",
            "pep8-naming",
        ],
    },
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
