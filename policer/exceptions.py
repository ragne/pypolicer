# coding=utf-8
"""Exception storage"""


class ConfigNotFound(Exception):
    """Raises when config file is not found in filesystem"""
    pass


class DatabaseError(Exception):
    """Raises when database error happend. Wraps many of rethinkdb exceptions"""
    pass
