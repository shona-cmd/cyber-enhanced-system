from setuptools import setup, find_packages

setup(
    name="naashon-secure-iot",
    version="1.0.0",
    author="Naashon Kuteesa",
    author_email="naashon.kuteesa@mtac.edu",
    description="A hybrid framework for enhancing cybersecurity in the "
    "Internet of Things at MTAC",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    packages=find_packages(),
    install_requires=[
        "torch>=2.0.0",
        "cryptography>=41.0.0",
        "flask>=2.3.0",
        "web3>=6.0.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "scikit-learn>=1.3.0",
        "matplotlib>=3.7.0",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Security",
        "Topic :: Internet of Things",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "naashon-secure-iot=naashon_secure_iot.core:main",
        ],
    },
)
