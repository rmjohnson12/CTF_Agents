"""Single source of truth for the distribution version.

``pyproject.toml`` reads ``__version__`` from here via setuptools' dynamic
``attr`` hook, which resolves the literal without importing the package. Nothing
else in the tree should hard-code a version string.
"""

__version__ = "2.6.0"
