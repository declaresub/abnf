# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from setuptools.command.test import test as TestCommand
import io
import sys
import string

PACKAGE_NAME = 'abnf'

def package_version(pkg_name=PACKAGE_NAME):
    with io.open(os.path.join(pkg_name, '__init__.py'), 'r', encoding='utf-8') as f:
        for sourceline in f:
            if sourceline.strip().startswith('__version__'):
                return sourceline.split('=',
                                        1)[1].strip(string.whitespace + '"\'')
        else:
            raise Exception('Unable to read package version.')


setup(
    name=PACKAGE_NAME,
    version=package_version(),
    description='Parsers for ABNF grammars.',
    long_description=
    'ABNF generates parsers for ABNF grammars. Though intended for use \
    RFC grammars, ABNF should handle any valid grammar.',
    author='Charles Yeomans',
    author_email='charles@declaresub.com',
    url='https://bitbucket.org/yeomans/abnf',
    packages=find_packages(exclude=["tests"]),
    keywords=['abnf', 'parser', 'generator'],
    classifiers=[
        'Development Status :: 4 - Beta', 'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Topic :: Software Development :: Build Tools',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6'
    ],
    license='MIT',
    python_requires='>=3',
    install_requires=[],
    zip_safe=False)
