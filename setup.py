# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

version = '1.0.0'

setup(
    name='ckanext-provbz-auth',
    version=version,
    description="",
    long_description="""\
        CKAN plugin for SPID authentication.
        Original repo at https://github.com/geosolutions-it/ckanext-provbz-auth
        """,
    classifiers=[],
    keywords='',
    author='Emanuele Tajariol',
    author_email='etj@geo-solutions.it',
    url='https://github.com/geosolutions-it/ckanext-provbz-auth',
    license='AGPL',
    packages=find_packages(exclude=['ez_setup', 'tests']),
    namespace_packages=['ckanext',
                        'ckanext.provbzauth',
                        'ckanext.provbzauth.repoze'],
    include_package_data=True,
    zip_safe=False,
    install_requires=[],
    setup_requires=['nose>=1.0', 'coverage'],
    tests_require=['nose'],
    message_extractors={
        'ckanext': [
            ('**.py', 'python', None),
            ('**/templates/**.html', 'ckan', None),
            ],
    },
    entry_points={
        'ckan.plugins': [
            'provbz_auth=ckanext.provbzauth.plugin:ProvBzAuthPlugin',
         ],
        'babel.extractors': [
            'ckan=ckan.lib.extract:extract_ckan',
         ],
    },
)
