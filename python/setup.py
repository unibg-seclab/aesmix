from setuptools import setup

with open('README.rst') as README:
    long_description = README.read()
    long_description = long_description[long_description.index('Description'):]

with open('requirements.txt', 'r') as fp:
    install_requires = [el.strip() for el in fp.readlines() if el.strip()]

setup(name='aesmix',
      version='0.1',
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
      install_requires=install_requires)
