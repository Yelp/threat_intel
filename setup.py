# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup

setup(
    name="threat_intel",
    version="0.0.1_a1",
    author="Yelp Security",
    setup_requires='setuptools',
    license='Copyright 2014 Yelp',
    author_email="opensource@yelp.com",
    description="Collection of the API calls for various threat intel feeds.",
    packages=find_packages(),
    install_requires=[
        "grequests==0.2.0",
        "simplejson==3.6.5",
    ],
)
