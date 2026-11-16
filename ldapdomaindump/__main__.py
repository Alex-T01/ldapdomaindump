#!/usr/bin/env python
# `python -m ldapdomaindump` dispatches to the same streaming/parallel
# collector as the `ldapdomaindump` console script - see the [project.scripts]
# comment in pyproject.toml for why.
from ldapdomaindump import ldd_stream
ldd_stream.main()
