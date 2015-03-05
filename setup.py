# -*- coding: utf-8 -*-
from __future__ import absolute_import

from setuptools import find_packages
from setuptools import setup

import threat_intel

setup(
    name="threat_intel",
    version=threat_intel.__version__,
    provides=['threat_intel'],
    author="Yelp Security",
    url='https://github.com/Yelp/threat_intel',
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    author_email="opensource@yelp.com",
    description="Collection of the API calls for various threat intel feeds.",
    packages=find_packages(exclude='tests*'),
    include_package_data=True,
    install_requires=[
        "grequests==0.2.0",
        "simplejson==3.6.5",
        "virtualenv",
    ],
)
