"""
Created on Nov 10, 2014

@author: Aitor Gómez Goiri <aitor.gomez@deusto.es>

To install/reinstall/uninstall the project and its dependencies using pip:
     pip install ./
     pip install ./ --upgrade
     pip uninstall liblightsec
"""
from setuptools import setup  # , find_packages

setup(name="liblightsec",
      version="0.1",
      description="Python implementation of Nist SP 800-108 KDF in Counter Mode",
      # long_description = "",
      author="Aitor Gomez-Goiri",
      author_email="aitor.gomez@deusto.es",
      maintainer="Aitor Gomez-Goiri",
      maintainer_email="aitor.gomez@deusto.es",
      url="https://github.com/lightsec/liblightsec",
      # license = "http://www.apache.org/licenses/LICENSE-2.0",
      platforms=["any"],
      package_dir={
          '': 'src',
      },
      packages=["lightsec"],
      # Or to include all packages under src...
      # from setuptools import find_packages
      # packages = find_packages('src'),

      install_requires=[
          "pynist800108"
      ],
      # entry_points = {}
      keywords="security lightweight sensor gateway authentication authorization iot things python",
)