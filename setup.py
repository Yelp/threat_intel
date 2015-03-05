# -*- coding: utf-8 -*-
from __future__ import absolute_import

from setuptools import find_packages
from setuptools import setup


setup(
    name="threat_intel",
    version='0.0.1a2',
    provides=['threat_intel'],
    author="Yelp Security",
    url='https://github.com/Yelp/threat_intel',
    setup_requires='setuptools',
    license='Copyright 2015 Yelp',
    author_email="team-security@yelp.com",
    description="Collection of the API calls for various threat intel feeds.",
    packages=find_packages(exclude='tests*'),
    install_requires=[
        "grequests==0.2.0",
        "simplejson==3.6.5",
    ],
)
