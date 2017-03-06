#!/usr/bin/env python3
# coding=utf-8
"""
Module for start the daemon and the api
Basic usage:
    `python -m policer -h`
"""

import sys
import os
import signal
import argparse
import logging

from daemonize import Daemonize

from .server import run, logger


def start_daemon(pidfile, log_file=None, log_level=logging.INFO):
    """
    Start application as a daemon, keep log_file fd
    :param pidfile: where pidfile should be created.
    :type pidfile: str
    :param log_file: where logfile should be created. If `None` log file created in working directory
    :type log_file: str
    :param log_level: level for logging (DEBUG, INFO, etc), defaults to `logging.INFO`
    :type log_level: int
    """
    if not log_file:
        log_file = "policer_server.log"
    fh = logging.FileHandler(log_file)
    formatter = logging.Formatter('[%(asctime)s] %(name)s — %(levelname)s — %(message)s')
    fh.setFormatter(formatter)
    fh.setLevel(log_level)
    logger.addHandler(fh)
    logger.propagate = False
    keep_fds = [fh.stream.fileno()]

    logger.debug("About to start a daemon")
    daemon = Daemonize(app="test_policer", pid=pidfile, action=run, keep_fds=keep_fds, logger=logger,
                       privileged_action=lambda: [log_level])  # only way to pass loglevel inside `run` action
    daemon.start()


def start_dev(log_level):
    """Should start developer server with autoreload, but autoreload is so terribad(relative imports inside package)
    Instead we just run it in foreground"""
    return run(log_level)


def stop_daemon(pidfile):
    """
    Stop the daemon
    """

    # noinspection PyShadowingNames
    def remove_pidfile(pidfile):
        """remove pidfile"""
        try:
            if os.path.exists(pidfile):
                os.remove(pidfile)
                return True
        except (OSError, IOError, BlockingIOError):
            logger.exception("Got error while deleting pidfile %s", pidfile)
            return False

    # Get the pid from the pidfile
    try:
        pf = open(pidfile, 'r')
        pid = int(pf.read().strip())
        pf.close()
    except IOError:
        pid = None

    if not pid:
        message = "pidfile %s does not exist. Daemon not running?"
        logger.error(message % pidfile)
        return True  # not an error in a restart

    # Try killing the daemon process
    try:
        os.kill(pid, signal.SIGTERM)
        logger.info("Daemon with pid: %d stopped successfuly", pid)
        return remove_pidfile(pidfile)
    except (OSError, ProcessLookupError) as err:
        msg = os.strerror(err)
        if isinstance(err, ProcessLookupError):
            return remove_pidfile(pidfile)
        else:
            logger.error("Got error while killing process with pid %d: %s", pid, msg)
            sys.exit(1)


def restart_daemon(pidfile):
    """Just restart, there is no need to check, if stop was succesfull,
       because if start cannot lock pidfile, it will fail gracefully"""
    stop_daemon(pidfile)
    logger.info("Starting daemon process.")
    return start_daemon(pidfile)


def main():
    """
    Server and api server runner, capable of:
        - run policer server as a daemon
        - run with different log levels
        - run in foreground
    :return:
    """
    from .utils import set_settings, settings
    # noinspection PyProtectedMember
    logging_choices = [v.lower() for v in logging._levelToName.values()] + list(logging._levelToName.values())

    # noinspection PyShadowingNames
    def is_valid_file(parser, arg):
        """Perform file existance validation
        :type parser: :class:`argparse.ArgumentParser`
        :arg parser: parser instance for return an error, if file is not valid
        :type arg: any
        :arg arg: filepath for validation
        :return: arg
            absolute path for given filename if it exists. It is for daemon process,
            because of explicit `cwd` call in Daemonize
        :rtype: any
        """
        if not os.path.exists(arg):
            parser.error("The file %s does not exist!" % arg)
        else:
            return os.path.abspath(arg)

    parser = argparse.ArgumentParser(description='Policer server runner')
    parser.add_argument('action', type=str, help='What action to perform',
                        choices=['start', 'stop', 'restart', 'startapi'])
    parser.add_argument('-f', '--no-daemon', dest='daemon', action='store_false',
                        help='Run in daemon mode(default)', default=True)
    parser.add_argument('-c', '--config', help='Use config provided as argument', default=None,
                        type=lambda arg: is_valid_file(parser, arg))
    parser.add_argument('--dev', action='store_true', help='Enable developer mode(foreground)')
    parser.add_argument('-l', '--level', type=str, help='Set log level to <value>',
                        choices=logging_choices, default='info')

    logger = logging.getLogger('policer.runner')
    args = parser.parse_args()
    if args.config:
        set_settings(args.config)

    log_level = logging.getLevelName(args.level.upper())
    logger.setLevel(log_level)

    pidfile = settings.get('Global.pid_file', '/tmp/policer.pid')
    act = args.action

    if act == 'startapi':
        from .api import app
        return app.run(debug=args.dev, host='0.0.0.0', port=7000)

    if act == 'start':
        if args.daemon:
            logger.warning('Daemon is started, refer to log file for futher details.')
            log_file = settings.get('Global.log_file')
            return start_daemon(pidfile, log_file, log_level)
        else:
            logger.warning('Daemon is started with developer mode(foreground).')
            return start_dev(log_level)
    elif act == 'restart':
        if not args.daemon:
            logger.warning("dev server is running. Nothing to restart")
        else:
            return restart_daemon(pidfile)
    elif act == 'stop':
        if not args.daemon:
            logger.warning("dev server is running. Nothing to stop")
        else:
            return stop_daemon(pidfile)


if __name__ == '__main__':
    try:
        sys.exit(int(main() or 0))
    except Exception:
        logger.exception("Exception in main!")
