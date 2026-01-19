# Configuration file for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys

# -- Project information -----------------------------------------------------
project = 'HookProbe'
copyright = '2024-2026, HookProbe Team'
author = 'HookProbe Team'
release = '5.9'

# -- General configuration ---------------------------------------------------
extensions = [
    'myst_parser',           # Markdown support
    'sphinx.ext.autodoc',    # Auto-generate docs from docstrings
    'sphinx.ext.viewcode',   # Add links to source code
    'sphinx.ext.napoleon',   # Google/NumPy docstring support
    'sphinx_copybutton',     # Copy button for code blocks
]

# MyST parser configuration
myst_enable_extensions = [
    'colon_fence',      # ::: directive syntax
    'deflist',          # Definition lists
    'fieldlist',        # Field lists
    'html_admonition',  # HTML admonitions
    'html_image',       # HTML images
    'replacements',     # Text replacements
    'smartquotes',      # Smart quotes
    'strikethrough',    # ~~strikethrough~~
    'substitution',     # Substitutions
    'tasklist',         # Task lists - [ ] and - [x]
]

myst_heading_anchors = 3  # Generate anchors for h1-h3

# Source file suffixes
source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

# The master toctree document
master_doc = 'index'

# Patterns to exclude
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# -- Options for HTML output -------------------------------------------------
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

# Theme options
html_theme_options = {
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'includehidden': True,
    'titles_only': False,
    'logo_only': False,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': True,
}

# Custom sidebar templates
html_sidebars = {
    '**': [
        'globaltoc.html',
        'relations.html',
        'searchbox.html',
    ]
}

# -- Options for linkcheck ---------------------------------------------------
linkcheck_ignore = [
    r'http://localhost.*',
    r'http://127\.0\.0\.1.*',
    r'https://mssp\.hookprobe\.com.*',
]

# Suppress warnings for missing references in markdown
suppress_warnings = ['myst.header']
