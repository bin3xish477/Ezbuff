import setuptools

setuptools.setup(name='ezfuzz',
      version='1.0',
      description='Ezfuzz is a Python package created to make fuzz testing an application easier.',
      url='https://github.com/binexisHATT/Ezfuzz',
      author='Alexis Rodriguez',
      author_email='rodriguez10011999@gmail.com',
      license='MIT',
      packages=setuptools.find_package(),
      classifiers=[
          "Programming Language :: Python :: 3",
          "License :: OSI Approved :: MIT License",
          "Operating System :: OS Independent",
    ],
    python_requires='>=3.6'
)
