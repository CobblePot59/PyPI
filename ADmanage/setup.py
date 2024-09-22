from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    long_description = f.read()

setup(
    name='ADmanage',
    version='0.9',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=find_packages(include=['ADmanage', 'ADmanage.*']),
    install_requires=[
        'ldap3',
        'six',
        'dnspython',
        'pycryptodome'
    ],
)