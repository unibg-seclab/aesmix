from setuptools import setup

with open('README.rst') as README:
    long_description = README.read()
    long_description = long_description[long_description.index('Description'):]

setup(name='aesmix',
      version='1.0',
      description='Mix&Slice',
      long_description=long_description,
      url='http://github.com/unibg-seclab/aesmix',
      author='Unibg Seclab',
      author_email='seclab@unibg.it',
      license='MIT',
      zip_safe=False,
      packages=['aesmix'],
      cffi_modules=['lib/build_aesmix.py:ffibuilder'],
      scripts=['scripts/mixslice'],
      setup_requires=['cffi'],
      install_requires=['cffi', 'pycryptodome', 'six'])
