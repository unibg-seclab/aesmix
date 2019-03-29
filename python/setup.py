from setuptools import setup

with open('requirements.txt', 'r') as fp:
    install_requires = [el.strip() for el in fp.readlines() if el.strip()]

setup(name='aesmix',
      version='1.0',
      description='Mix&Slice',
      url='http://github.com/unibg-seclab/aesmix',
      author='Unibg Seclab',
      author_email='seclab@unibg.it',
      license='MIT',
      zip_safe=False,
      packages=['aesmix'],
      cffi_modules=['build_aesmix.py:ffibuilder'],
      scripts=['scripts/mixslice'],
      setup_requires=['cffi'],
      install_requires=install_requires)
