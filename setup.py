#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

# Read requirements
requirements = []
with open('requirements.txt') as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="reverse-engineering-platform",
    version="1.0.0",
    author="RE Platform Team",
    author_email="team@replatform.dev",
    description="A comprehensive cross-platform reverse engineering toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/username/reverse-engineering-platform",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Debuggers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        'dev': [
            'pytest>=7.0.0',
            'black>=23.0.0',
            'isort>=5.12.0',
            'pylint>=2.17.0',
            'sphinx>=4.0.0',
        ]
    },
    entry_points={
        'console_scripts': [
            're-platform=src.main:main',
        ],
    },
    include_package_data=True,
    package_data={
        'src': ['resources/*', 'resources/**/*'],
    },
)
