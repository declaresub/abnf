# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import io
import sys
import string
import os

PACKAGE_NAME = 'abnf'

def meta(key, pkg_name=PACKAGE_NAME):
    with io.open(os.path.join('src', pkg_name, '__init__.py'), 'r', encoding='utf-8') as f:
        for sourceline in f:
            if sourceline.strip().startswith('__%s__' % key):
                return sourceline.split('=',
                                        1)[1].strip(string.whitespace + '"\'')
        else:
            raise Exception('Unable to find metadata key %s.', key)


setup(
    name=PACKAGE_NAME,
    version=meta('version'),
    description='Parsers for ABNF grammars.',
    long_description=
    'ABNF generates parsers for ABNF grammars. Though intended for use with \
    RFC grammars, ABNF should handle any valid grammar.',
    author=meta('author'),
    author_email=meta('author_email'),
    url=meta('project_url'),
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    keywords=['abnf', 'parser', 'generator'],
    classifiers=[
        'Development Status :: 4 - Beta', 'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Build Tools',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8'
    ],
    license=meta('license'),
    python_requires='>=3',
    install_requires=[],
    zip_safe=False,
    options={"bdist_wheel": {"universal": "1"}})
