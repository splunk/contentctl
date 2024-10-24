#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup


setup(
    use_calver="%Y%m%d.%H.%M",
    setup_requires=['calver==2022.6.26']
)
