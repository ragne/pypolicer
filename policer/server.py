#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Heart of the policer. All filtering goes through it.

Notes: due to email sending mechanism, all your CC, BCC, multiple recipients appears to server one by one.
i.e you have send mail to a@example.com, b@example.com and cc to: d@example.org,
so server recieved three(3!) independent entry with each addr as recipient
"""
from __future__ import print_function
import pprint
import re
import logging
import codecs
import time
import sys

from gevent.server import StreamServer
from gevent.pool import Pool
from gevent import socket, spawn
from .utils import settings, monitor_changes

from .checks import Checks, BasicCheck, StatisticsCollector, Action, BlockDeliveryForAll

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(name)s %(message)s')
# pylint: disable=C0103
logger = logging.getLogger('policer.server')


def failed_result(action, reason=''):
    """
    Shortcut for returning failed result
    :param action: action from :class:`~checks.Checks`
    :param reason: reason for the mail server, which send to the client
    :return: formatted tuple, which returned to mail server
    :rtype tuple
    """
    return action, reason, False


def success_result(action, reason=''):
    """
    Shortcut for returning succesfull result, same as :func:`failed_result`
    :param action: action one of enum :class:`~checks.Checks`
    :param reason: reason for the mail server, which send to the client
    :return: formatted tuple, which returned to mail server
    :rtype: tuple
    """
    return action, reason, True


def get_checks_for_user(buf):
    """
    Get enabled checks for user in `buf` and global checks for all users.
    :param buf: Buffer, as it send by the wire(from mail server)
    :return: list of checks
    :rtype: list
    """
    b = BasicCheck(buf)
    request = buf.get(b'request', None)  # <- this is required attribute (buf there is still in
    #                                                          binary format, as it get by the wire)
    if not request:
        raise ValueError("Got malformed request from server! Required attribute \"request\" was not"
                         "found.Please read man on http://www.postfix.org/SMTPD_POLICY_README.html")
    # direction_map = { "smtpd_access_policy": "sender", None: None }
    # Explore this part of postfix docs
    # After exploring code, no more usages for const `MAIL_ATTR_REQ` found in policy+check usecase
    #
    # Collect statistics for every recipient, including those that are not in DB.
    defaults = [BlockDeliveryForAll, StatisticsCollector]
    defaults = list(settings.get_default_checks()) or defaults

    checks = b.get_enabled_checks()
    if checks:
        checks_list = sorted([Checks.get(v) for v in checks if Checks.get(v) is not None],
                             key=lambda x: x.Meta.priority)

        if StatisticsCollector not in checks_list:
            defaults.extend(checks_list)
            return reversed(defaults)
        else:
            return checks_list
    return defaults


def logic_handler(buf, checks=None, fail_at_once=True):
    # result tuple format, ('action'->['reject', 'permit', 'defer', 'defer_if_permit', 'defer_if_reject'],
    # 'reason'->'no address found', 'status'->['True', 'False'])
    # fail_at_once:
    """

    :param buf:  Buffer, as it send by the wire(from mail server)
    :param checks: List of tests to check
    :type checks: list
    :param fail_at_once: when one of filters in chain fail, should all chain fail as well
    :type fail_at_once: bool
    :return: tuple of three items (action, reason, truth)
    :rtype: tuple
    """
    results = []
    if not checks:
        checks = get_checks_for_user(buf)
    for check_class in checks:
        start = time.time()
        check = check_class(buf, logger=logger)
        res = check.check()
        stop = time.time() - start
        logger.debug("Function %s.check() takes %.2f time to complete", check.__class__.__name__, stop)
        if fail_at_once and (not res[2]):
            return res
        results.append(res)
    logger.debug("result: %s", results)
    if any((res[2] for res in results)):
        return success_result(Action.PERMIT)
    else:
        return failed_result(Action.REJECT)


def format_result(result):
    """
    Format result for the mail server
    :param result: result from :func:`logic_handler`
    :return: formatted result as string
    :rtype: str
    """
    return "action={} {}\n\n".format(result[0], result[1])


def mainloop(sock, address):
    """
    Mainloop of our server, called for new connection. Parse lines, send by mail server, create buffer of those lines
    and send buffer to :func:`logic_handler`.
    For postfix protocol info refer to: http://www.postfix.org/SMTPD_POLICY_README.html
    :param sock: client socket with accepted connection
    :type sock: `gevent.socket.socket`
    :param address: client address
    :type address: tuple
    :return:
    """
    line_re = re.compile(b"([^=]+)=(.*)")
    logger.info('New connection from %s:%s', *address)

    # using a makefile because we want to use readline()
    rfileobj = sock.makefile(mode='rb')
    buf = {}
    while True:
        line = rfileobj.readline().strip()
        logger.debug("Client sent line: %s", line)
        # noinspection PyBroadException
        try:
            m = line_re.match(line)
            if m:
                name, value = m.groups()
                buf[name] = value
                continue
            elif not line or line == b'':
                # client end data stream
                logger.info("Client %s:%s finished sending SPF data", *sock.getpeername())
                logger.debug("Content of buffer: %s", pprint.pformat(buf))
                start = time.time()
                result = format_result(logic_handler(buf))
                logger.debug("Total time taken for logic: %.2f", time.time() - start)
                logger.info("Decision: %s", result)
                # for escape_decode see this answer http://stackoverflow.com/a/37059682/6468301
                sock.send(codecs.escape_decode(result.encode('unicode_escape'))[0])
                logger.debug("Total time taken for logic+sending: %.2f", time.time() - start)
                break
            else:
                logger.warning("Received utter garbage: %.100s", line)

        except (ValueError, TypeError, AttributeError):
            logger.exception("Exception in main parsing loop, send DUNNO to postfix")
            sock.send(b'action=DUNNO some internal error\n\n')
            break
        # Catch all exceptions, because we need to send result to the server anyway, so we sent DUNNO to it.
        except Exception:
            logger.exception("Unknown exception in mainloop")
            sock.send(b'action=DUNNO unknown exception occured\n\n')
            break
    rfileobj.close()


def run(loglevel=None, db_host='127.0.0.1'):
    """Run server mainloop with gevent pool.
       Server can listen on network address or unix socket
       Also, this function spawn greenlet, who's monitor config changes and reload it
       Global state - some db, backed up in .db.py, acl like big key-value storage
    """
    import os
    from policer.db import GlobalState
    from policer.exceptions import DatabaseError
    if loglevel:
        logger.setLevel(loglevel)
    pool = Pool(1000)

    enable_socket = settings.as_bool('Global.enable_socket', False)
    # before we start mainloop, we should check and issue a warning if settings is empty,
    # even if settings is empty, it doesn't stop us from running a server
    if not settings:
        logger.warning("No config file were provided or it's empty!")
    # to make the server use SSL, pass certfile and keyfile arguments to the
    # constructor
    # for now only one of socket or tcp listener can be enabled, not both.
    if enable_socket:
        # noinspection PyUnresolvedReferences
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sockname = settings.get('Global.sock_file', '/tmp/policer.sock')
        if os.path.exists(sockname):
            os.remove(sockname)
        else:
            os.makedirs(os.path.dirname(sockname))
        listener.bind(sockname)
        listener.listen(1)
        logger.info('Starting echo server on unix:%s', sockname)
    else:
        address = settings.get('Global.listen', '127.0.0.1')
        port = settings.as_int('Global.port', 16000)
        listener = (address, port)
        logger.info('Starting echo server on port %s:%d', address, port)

    server = StreamServer(listener, mainloop, spawn=pool)

    try:
        spawn(monitor_changes, logger)
        global_state = GlobalState(hostname=db_host)
        # we use blocking serve_forever() here because we have no other jobs
        server.serve_forever()
    except DatabaseError:
        logger.error("Database problem!", exc_info=True)
        sys.exit(1)
    except KeyboardInterrupt:
        # noinspection PyUnboundLocalVariable
        # because we specially look for KeyboardInterrupt when we run in foreground
        global_state.save()
        logger.info("Server stopped!")
    finally:
        server.stop()


if __name__ == '__main__':
    run(10)
