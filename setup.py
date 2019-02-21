# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup


setup(
    name="threat_intel",
    version='0.1.29',
    provides=['threat_intel'],
    author="Yelp Security",
    url='https://github.com/Yelp/threat_intel',
    setup_requires='setuptools',
    license='Copyright 2016 Yelp',
    author_email="opensource@yelp.com",
    description="Collection of the API calls for various threat intel feeds.",
    packages=find_packages(),
    install_requires=[
        "requests-futures>=0.9.9",
        "requests[security]>=2.20.0",
        "simplejson>=3.10.0",
        "six>=1.10.0",
    ],
)
