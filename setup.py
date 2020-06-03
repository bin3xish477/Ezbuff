import setuptools
from os import path

directory = path.abspath(path.dirname(__file__))
with open(path.join(directory, 'README.md'), 'r') as f:
    long_description = f.read()

setuptools.setup(
      name='ezbuff',
      version='1.0',
      description='Ezbuff is a Python package created to automate some steps of the 2020 PWK buffer overflow.',
      long_description=long_description,
      long_description_content_type='text/markdown',
      url='https://github.com/binexisHATT/Ezfuzz',
      author='Alexis Rodriguez',
      author_email='rodriguez10011999@gmail.com',
      license='MIT',
      packages=setuptools.find_packages(),
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
    ],
    python_requires='>=3.6'
)
