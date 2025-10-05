from __future__ import annotations
import os
import sys
from datetime import datetime
from importlib.metadata import version, PackageNotFoundError

# Ensure package is importable (RTD checks out the repo root)
sys.path.insert(0, os.path.abspath(".."))

project = "manifest-wizard"
author = "Antonio D'Angelo"
copyright = f"{datetime.now():%Y}, {author}"

try:
    release = version("manifest-wizard")
except PackageNotFoundError:
    release = "0.1.0"

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx_autodoc_typehints",
]

myst_enable_extensions = ["colon_fence", "deflist"]

templates_path = ["_templates"]
exclude_patterns = []

html_theme = "furo"
html_title = project

# Autodoc settings
autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "show-inheritance": True,
}
autodoc_typehints = "description"
