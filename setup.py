# Metadata now lives in pyproject.toml (PEP 621).
# This shim keeps `python setup.py ...` working for legacy workflows.
from setuptools import setup
setup()
