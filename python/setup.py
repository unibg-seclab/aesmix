from setuptools import setup

with open('README.rst') as README:
    long_description = README.read()
    long_description = long_description[long_description.index('Description'):]

setup(name='aesmix',
      version='1.6',
      description='Mix&Slice',
      long_description=long_description,
      url='http://github.com/unibg-seclab/aesmix',
      author='Unibg Seclab',
      author_email='seclab@unibg.it',
      license='MIT',
      zip_safe=False,
      include_package_data=True,
      packages=['aesmix'],
      cffi_modules=['lib/build_aesmix.py:ffibuilder'],
      scripts=['scripts/mixslice'],
      setup_requires=['cffi>=1.12'],
      install_requires=['cffi>=1.12', 'pycryptodome', 'six'])
