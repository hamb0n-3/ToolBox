#!/usr/bin/env python3
# Setup script for installing the file_analyzer package

from setuptools import setup, find_packages
import os
import re

# Read version from file_analyzer/__init__.py
with open(os.path.join('file_analyzer', '__init__.py'), 'r') as f:
    version_match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", f.read(), re.M)
    if version_match:
        version = version_match.group(1)
    else:
        version = '0.1.0'

# Read long description from README.md
try:
    with open('README.md', 'r') as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = 'A comprehensive file analysis tool for cybersecurity'

# Core dependencies
install_requires = [
    'tqdm>=4.65.0',
    'colorama>=0.4.6',
]

# Optional dependencies
extras_require = {
    'code_analysis': [
        'astroid>=2.11.0',
        'radon>=5.1.0',
    ],
    'ml': [
        'scikit-learn>=1.0.0',
        'joblib>=1.1.0',
    ],
    'nlp': [
        'spacy>=3.4.0',
    ],
    'binary': [
        'pefile>=2023.2.7',
        'pyelftools>=0.29',
        'macholib>=1.16',
        'python-magic>=0.4.27',
    ],
    'all': [
        'astroid>=2.11.0',
        'radon>=5.1.0',
        'scikit-learn>=1.0.0',
        'joblib>=1.1.0',
        'spacy>=3.4.0',
        'pefile>=2023.2.7',
        'pyelftools>=0.29',
        'macholib>=1.16',
        'python-magic>=0.4.27',
    ]
}

setup(
    name='file-analyzer',
    version=version,
    description='A comprehensive file analysis tool for cybersecurity',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Tristan Pereira',
    author_email='your.email@example.com',  # Replace with your email
    url='https://github.com/yourusername/file-analyzer',  # Replace with your GitHub repo
    packages=find_packages(),
    install_requires=install_requires,
    extras_require=extras_require,
    entry_points={
        'console_scripts': [
            'file-analyzer=file_analyzer.main:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
    python_requires='>=3.7',
) 