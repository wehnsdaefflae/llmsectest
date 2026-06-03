"""Packaged OWASP probe suite run by the ``llmsectest`` CLI.

These pytest modules drive the curated corpus in :mod:`llmsectest.probes`
against a target adapter resolved from the ``LLMSECTEST_TARGET`` environment
variable (default: the offline demo target). A failing test is a *finding* —
the SARIF/HTML/JSON/Markdown reports are generated from the failures.
"""
