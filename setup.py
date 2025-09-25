from setuptools import setup, find_packages

setup(
    name='inspector-cli',
    version='1.1.1',
    author='Aegis Martin',
    description='A modular cybersecurity CLI tool for scanning, recon, and malware analysis.',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/bmp-43/INSPECTOR-CLI.git',
    packages=find_packages(include=['inspector_cli', 'inspector_cli.*']),
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
            'inspector = inspector_cli.inspector:launch'  # check this matches your function name
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'Operating System :: OS Independent',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    ],
    license='GPLv3',
    python_requires='>=3.8',
)
