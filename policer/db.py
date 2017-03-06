#!/usr/bin/env python
# coding=utf-8
"""
This module contains not so perfect implementation of GlobalStorage class. Which puprose to store info from RethinkDB
and serve it to user via simplified interface(i.e ORM)
"""

import errno
import logging
import os
import signal
from functools import wraps
from time import time

import rethinkdb as r

from policer.exceptions import DatabaseError

logger = logging.getLogger("policer.db")

DB_NAME = 'mail_policer'


def get_connection(hostname):
    """
    Returns rethinkDB connection object

    :param hostname: address to connect
    :return: connection
    :rtype: :class:`rethinkdb.net.Connection`
    """
    port = r.DEFAULT_PORT
    db = DB_NAME
    try:
        conn = r.connect(hostname, port, db)
        if not r.db_list().contains('db').run(conn):
            init_db(r.connect(hostname, port, db))
        return conn
    except (r.errors.ReqlError, r.errors.ReqlDriverError) as e:
        raise DatabaseError(e)


def get_or_create(oid, conn):
    """get_or_create copycat'd from django to rethink

    :param oid: object id
    :param conn: connection returned by :func:`~db.get_connection`
    """
    tbl = conn.db(DB_NAME).table('senders')
    try:
        item = tbl.get(oid)
    except r.ReqlOpFailedError:
        item = {'id': oid}
    return item


def save(item, conn):
    """save item using connection"""
    tbl = r.db(DB_NAME).table('senders')
    tbl.insert(item, conflict="replace").run(conn)


def init_db(connection):
    """Initialize database. Create nessesary tables"""
    db_name = DB_NAME
    table_name = 'senders'
    try:
        r.db_create(db_name).run(connection)
        r.db(db_name).table_create(table_name).run(connection)
    except r.RqlRuntimeError:
        pass
    finally:
        connection.close()


class DotDict(dict):
    """
    a dictionary that supports dot notation as well as dictionary access notation

    **usage**:

    >>> d = DotDict()
    >>> d = DotDict({'val1':'first'})

    **set attributes**:

    >>> d.val2 = 'second'
    >>> d['val2'] = 'second'

    **get attributes**:

    >>> d.val2
    >>> d['val2']
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__


def dict_compare(d1, d2):
    """
    Compare two dictionaries by keys and return difference

    :param d1: Dictionary to compare
    :param d2: Dictionary to compare
    :return: tuple of (Modified as bool, modified keys as list)
    :rtype: tuple
    """
    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    intersect_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o: (d1[o], d2[o]) for o in intersect_keys if d1[o] != d2[o]}
    keys = (added or removed or modified)
    return bool((added or removed or modified) or set()), keys


class GlobalState:
    """Global storage, acts dict-like tiny proxy in front of rethinkDB.
    Functions:

    * autosave by timeout
    * fast get and set
    * delayed save

    In some cirrumstances you can lose your data (i.e not force save and sigterm/sigkill/poweroff)
    """
    def __init__(self, hostname, update_time=10, save_time=10):
        """update_time and save_time in seconds"""
        self.update_time = update_time
        self.save_time = save_time
        self.now = time()
        self.storage = DotDict()
        self.server_data = dict()
        self.initialized = True
        try:
            self.connection = get_connection(hostname)
            self.update()
        except (TimeoutError, DatabaseError):
            self.connection = None
            logger.warning("Rethinkdb is not active, so save and update functions are disabled")

    def __setitem__(self, key, value):
        self.storage[key] = value
        if self.is_save_time():
            self.save()

    def __getitem__(self, item):
        if self.is_update_time():
            self.update()
        return self.storage.__getitem__(item)

    def __delitem__(self, item):
        # enforce update
        self.update()
        if item in self.storage:
            del self.storage[item]
            r.table('senders').get(item).delete().run(self.connection)
        else:
            raise KeyError("Key not found")

    def items(self):
        """Dict-like items() method, but updated with data from server"""
        if self.is_update_time():
            self.update()
        return self.storage.items()

    def get(self, item, default=None):
        """Dict-like get method, but updated with data from server"""
        self.update()
        if item in self.storage:
            return self.storage[item]
        return default

    def diff_storages(self):
        """
        Compare `self.storage` with data from server and return result

        :return: result of comparation (truth, modified keys)
        :rtype: tuple
        """
        self.update(container=self.server_data)
        truth, keys = dict_compare(self.storage.__dict__, self.server_data)
        return truth, keys

    def is_save_time(self):
        """
        Determines if inner struct should be save based on `self.save_time`

        :return:
        :rtype: bool
        """
        if self.diff_storages()[0]:
            return True
        now = time()
        is_save = now > self.now + self.save_time
        # print("now: {}, update: {}, perform update: {}".format(ctime(now), ctime(self.now + self.save_time),
        # is_save))
        if is_save:
            self.now = now
        return is_save

    def save_changed(self):
        """
        Saves changed object in `self.storage`

        :return: True if some objects been saved, else False
        :rtype: bool
        """
        if self.connection:
            keys = self.diff_storages()[1]
            for pk in keys:
                item = self.storage[pk]
                im = {'id': pk}
                im.update(item)
                save(im, self.connection)
            return True if keys else False
        return False

    def is_update_time(self):
        """
        Determines if inner struct should be updated based on `self.update_time`

        :return:
        :rtype: bool
        """
        now = time()
        # print("now: {}, update: {}, perform update: {}".format(ctime(now), ctime(self.now + self.update_time),
        # now > self.now + self.update_time))
        is_time = now > self.now + self.update_time
        if is_time:
            self.now = now
        return is_time

    def save(self, force=False):
        """
        Saves data in `self.storage` if something is changed, or rewrite everything if force is specified

        :param force: rewrite everything if specified
        """
        if self.connection:
            if force:
                for item in self.storage.items():
                    im = {'id': item[0]}
                    im.update(item[1])
                    save(im, self.connection)
            else:
                self.save_changed()

    def update(self, container=None):
        """
        Update items in `container` from database

        :param container: container to update, defaults to `self.storage`
        """
        if self.connection:
            if container is None:
                container = self.storage
            tbl = r.table('senders')
            for row in tbl.filter("").run(self.connection):
                _id = row.pop('id')
                container[_id] = row
