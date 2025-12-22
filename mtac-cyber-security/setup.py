"""
Setup script for NaashonSecureIoT framework.
Supports cross-platform installation and QR code deployment.
"""

from setuptools import setup, find_packages
import os

# Read requirements
def read_requirements():
    with open('requirements.txt', 'r') as f:
        return [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Read README
def read_readme():
    if os.path.exists('README.md'):
        with open('README.md', 'r', encoding='utf-8') as f:
            return f.read()
    return ""

setup(
    name="naashon-secure-iot",
    version="1.0.0",
    author="NaashonSecureIoT Team",
    author_email="security@naashon-iot.com",
    description="Multi-layered IoT cybersecurity framework with zero-trust architecture",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/naashon/naashon-secure-iot",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Internet :: WWW/HTTP",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "gpu": [
            "torch[cuda]>=2.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "naashon-iot=naashon_secure_iot.core:main",
            "naashon-dashboard=naashon_secure_iot.dashboard:main",
            "naashon-qr-deploy=naashon_secure_iot.utils.qr_deploy:main",
        ],
    },
    include_package_data=True,
    package_data={
        "naashon_secure_iot": [
            "templates/*.html",
            "static/*",
            "models/*",
            "config/*.yaml",
        ],
    },
    zip_safe=False,
    keywords="iot security cybersecurity blockchain zero-trust machine-learning",
    project_urls={
        "Bug Reports": "https://github.com/naashon/naashon-secure-iot/issues",
        "Source": "https://github.com/naashon/naashon-secure-iot",
        "Documentation": "https://naashon-secure-iot.readthedocs.io/",
    },
)
