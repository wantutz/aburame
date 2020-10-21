from setuptools import setup
from setuptools import find_packages

setup(
    name='sxswagger',
    version='2.1.3',
    license='proprietary',
    description='ShieldX Common Test Infrastructure - Release 2.1',
    author='ShieldX Sharks',
    author_email='sharks@shieldx.com',

    packages = find_packages(where='src'),
    package_dir={'': 'src'},

    install_requires = [
        'boto3',
        'dotmap',
        'pytest',
        'pytest-datadir',
        'pyyaml',
        'pyVim',
        'pyVmomi',
        'requests',
    ],
)
