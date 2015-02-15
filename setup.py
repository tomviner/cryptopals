from setuptools import setup

setup(
    name='cryptopals',
    packages=['cryptopals'],
    install_requires=[
        'pycrypto'
    ],
    tests_require=[
        'tox',
        'pytest',
        'pytest-cov',
        'pytest-cache',
        'pytest-runfailed',
    ],
    include_data=True,
)
