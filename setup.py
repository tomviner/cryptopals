from setuptools import setup, find_packages

setup(
    name='cryptopals',
    packages=find_packages(),
    install_requires=[
        'pycrypto'
    ],
    tests_require=[
        'tox',
        'pytest',
        'pytest-cov',
        'pytest-cache',
        'pytest-runfailed',
        'pytest-mock',
    ],
    include_data=True,
)
