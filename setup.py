# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages

from djangosaml2idp import __version__

setup(
    name='djangosaml2idp',
    version=__version__,
    description='SAML 2.0 Identity Provider for Django',
    keywords="django,pysaml2,sso,saml2,federated authentication,authentication,idp",
    author='Mathieu Hinderyckx',
    author_email='mathieu.hinderyckx@gmail.com',
    maintainer="Mathieu Hinderyckx",
    long_description="\n\n".join([
        open(os.path.join(os.path.dirname(__file__), 'README.rst')).read(),
        #open('HISTORY.rst').read()
    ]),
    install_requires=[
        'django>=2.0',
        'pysaml2>=4.5.0'
        ],
    license='MIT',
    packages=find_packages(exclude=["tests*", "docs"]),
    url='https://github.com/OTA-Insight/djangosaml2idp/',
    zip_safe=False,
    include_package_data=True,
    classifiers=[
        "Development Status :: 3 - Alpha",
        'Environment :: Web Environment',
        "Framework :: Django",
        "Framework :: Django :: 2.0",
        "Framework :: Django :: 2.1",
        'Intended Audience :: Developers',
        "License :: OSI Approved :: MIT License",
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
