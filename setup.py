# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name="threat_intel",
    version="0.0.1",
    author="Yelp Security",
    author_email="opensource@yelp.com",
    description="Collection of the API calls for various threat intel feeds.",
    packages=["threat_intel"],
    install_requires=[
        "grequests==0.2.0",
        "simplejson==3.6.5",
    ],
)
