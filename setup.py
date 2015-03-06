# -*- coding: utf-8 -*-

from setuptools import setup, find_packages


setup(
    name="threat_intel",
    version='0.0.1a6',
    provides=['threat_intel'],
    author="Yelp Security",
    url='https://github.com/Yelp/threat_intel',
    setup_requires='setuptools',
    license='Copyright 2015 Yelp',
    author_email="team-security@yelp.com",
    description="Collection of the API calls for various threat intel feeds.",
    #packages=['threat_intel', 'threat_intel.util'],
    packages=find_packages(),
    install_requires=[
        "grequests==0.2.0",
        "simplejson==3.6.5",
    ],
)
