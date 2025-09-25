# setup.py
from setuptools import setup, find_packages

setup(
    name='inspector-cli',
    version='1.1.0',
    author='Aegis Martin',
    description='A modular cybersecurity CLI tool for scanning, recon, and malware analysis.',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/bmp-43/INSPECTOR-CLI.git',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests',
        'colorama',
        'pyfiglet',
        'dnspython',
        'python-whois',
        'ipwhois',
        'aiohttp'
    ],
    entry_points={
        'console_scripts': [
            'inspector = inspector_cli.inspector:weapon'
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    python_requires='>=3.7',
)
