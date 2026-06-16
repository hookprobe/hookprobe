"""Shared, dependency-free primitives usable by any shared/ subsystem.

This package exists so that sibling subsystems (shared/dsm, shared/mesh, ...)
can share small pure-stdlib helpers WITHOUT creating cross-subsystem import
cycles (e.g. mesh already imports dsm, so the shared helper cannot live in
either). Everything here must depend only on the Python standard library so it
is safe to vendor into minimal deployments (Sentinel, the DSM container).
"""
