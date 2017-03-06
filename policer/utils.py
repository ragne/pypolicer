"""
Utility modules

load_class - import class by dotname
"""
import inspect
import importlib
import os
import logging
import sys
import configobj

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import gevent

from .exceptions import ConfigNotFound


def load_class(classpath):
    """Import class by dotpath like "mymodule.TestClass"
    If module can't be imported return None, if loaded item is not a class, return None
    """
    components = classpath.split(':')
    try:
        mod = importlib.import_module(components[0])
    except ImportError:
        return None

    for comp in components[1:]:
        try:
            mod = getattr(mod, comp)
        except AttributeError:
            return None
    if not inspect.isclass(mod):
        return None
    return mod


def read_conf_file(filename):
    """Read config file and return configObj for it"""
    if os.path.exists(filename):
        try:
            return Config(filename)
        except configobj.ConfigObjError:
            return None
    return None


def get_conf_file():
    """ Try to find config file in those pathes and load config from it

    * /etc/pypolicer/pypolicer.conf
    * ~/.pypolicer.conf
    * ./policer.conf

    """
    for file in ['/etc/pypolicer/pypolicer.conf', '~/.pypolicer.conf', './policer.conf']:
        if os.path.exists(os.path.expanduser(file)):
            return Config(os.path.realpath(os.path.expanduser(file)))
    return Config(None)


class Config(configobj.ConfigObj):
    """Extended configobj class"""

    def __init__(self, infile, **kwargs):
        try:
            super(Config, self).__init__(infile, **kwargs)
        except configobj.ConfigObjError as e:
            logging.getLogger("policer.server").error(e)
            sys.exit(1)

    def get_default_checks(self):
        """Get checks from config, try to load them and return to user"""
        if 'global_plugins' in self:
            return filter(lambda x: x is not None, [load_class(x) for x in self['global_plugins']])
        return []

    def get_settings_for_plugin(self, pluginname):
        """Get global settings for pluginname from config section"""
        if pluginname in self:
            return self[pluginname]
        return {}

    def _get_dotted_path(self, path, method='get', default=None):
        try:
            if '.' in path:
                sec = self
                *sections, key = path.split('.')
                for section in sections:
                    sec = sec.get(section, {})
                    if not sec:
                        return default
                return getattr(sec, method, lambda k: default)(key)
            return getattr(super(Config, self), method, lambda k: default)(path)
        except (KeyError, ValueError):
            return default

    def get(self, key, default=None):
        """Same as :func:`configobj.Section.get`, but with dotted path notation too"""
        return self._get_dotted_path(key, default=default)

    def as_bool(self, key, default=None):
        """Like :func:`configobj.Section.as_bool`, but accepts dotted path too.

        **should return None if value not found:**

        >>> c = Config()
        >>> c.as_bool('Global.enable_socket')

        """
        return self._get_dotted_path(key, 'as_bool', default=default)

    def as_float(self, key, default=None):
        """Like :func:`configobj.Section.as_float`, but accepts dotted path too."""
        return self._get_dotted_path(key, 'as_float', default=default)

    def as_int(self, key, default=None):
        """Like :func:`configobj.Section.as_int`, but accepts dotted path too."""
        return self._get_dotted_path(key, 'as_int', default=default)

    def as_list(self, key, default=None):
        """Like :func:`configobj.Section.as_list`, but accepts dotted path too."""
        return self._get_dotted_path(key, 'as_list', default=default)


settings = get_conf_file()


def load_conf(filename):
    """Load config from filename

    :param filename: path to the config file
    :type filename: str
    :return: actual config object
    :rtype: :class:`~utils.Config`
    :raises: ConfigNotFound - when filename isn't found
    """
    if os.path.exists(os.path.expanduser(filename)):
        return Config(os.path.realpath(os.path.expanduser(filename)))
    else:
        raise ConfigNotFound("No file %s was found!" % filename)


def set_settings(filename):
    """
    Load config from filename and sets global settings variables
    Why global? Because of need to specify custom paths to config file and all
    pieces of the policer system imports settings from here.

    :param filename: path to the config file
    :type filename: str
    """
    settings.filename = filename
    settings.reload()


class EventHandler(FileSystemEventHandler):
    """Handler that reload config on modify `filename`"""

    def __init__(self, logger=None, filename=None):
        self.logger = logger
        self.filename = filename
        super(EventHandler, self).__init__()

    def on_modified(self, event):
        """
        Called when MODIFY event occured

        :param event: The event object representing the file system event.
        :type event: :class:`watchdog.events.FileSystemEvent`
        :return:
        """
        fullpath = event.src_path
        if self.filename in fullpath:
            self.logger.debug('Detected a modification on [%s]', fullpath)
            settings.reload()


def monitor_changes(logger=None):
    """
    Monitor changes to settings file and reload it, when file modifies
    :param logger:
    :return:
    """
    from .server import logger as s_log
    if not settings.filename:
        return
    ev_h = EventHandler(s_log, settings.filename)
    monitor = Observer()
    s_log.warn("path detected: %s[%s]", settings.filename,
               os.path.abspath(os.path.dirname(settings.filename)))
    monitor.schedule(ev_h, os.path.abspath(os.path.dirname(settings.filename)), recursive=False)
    monitor.start()
    try:
        while True:
            gevent.sleep(1)
    except KeyboardInterrupt:
        monitor.stop()
    monitor.join()


if __name__ == '__main__':
    def main():
        """Main. for testing only"""
        logger = logging.getLogger("policer.server")
        logger.setLevel(logging.DEBUG)
        console = logging.StreamHandler()
        console.setLevel(10)
        logger.addHandler(console)
        g = gevent.spawn(monitor_changes, logger)
        try:
            while True:
                gevent.sleep(1)
        except KeyboardInterrupt:
            g.kill()
            print("Exit...")


    main()
