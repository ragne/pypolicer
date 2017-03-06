#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Contains all implemented checks(also known as plugins)

"""
from enum import Enum
from .db import GlobalState
import re
import time
import json
from .utils import settings as config


class Action(Enum):
    """
    Enum of possible actions, that can be used in return codes
    """
    REJECT = 0
    PERMIT = 1
    DEFER = 2
    DEFER_IF_PERMIT = 3
    DEFER_IF_REJECT = 4
    DUNNO = 5
    REDIRECT = 6

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()


class ClassProperty(property):
    """
    Way to make a class property, only getters supported
    Another way to use a metaclass, like in this SO answer
    http://stackoverflow.com/questions/128573/using-property-on-classmethods
    """

    def __get__(self, cls, owner):
        return self.fget.__get__(None, owner)()


class BasicCheck(object):
    """
    Abstract class, parent for any check for the server
    Provides utilites and reduces boilerplate
    """

    class Meta:
        """
        Class with settings and metadata, inspired by Django Meta.
        """
        name = 'basic_check'
        prefix = 'c'
        priority = 1
        json_fields = {}

    default_statistics = {"counters": {
        "send": {}
    }}
    statistics_name = "statistics"

    @classmethod
    def get_name(cls):
        """
        Get class name with prefix.

        :return: classname with prefix from Meta
        :rtype: str
        """
        return '_'.join([BasicCheck.Meta.prefix, cls.Meta.name])

    name = ClassProperty(get_name)

    def __init__(self, buf, logger=None, dbhost="127.0.0.1"):
        if not logger:
            import logging
            logging.basicConfig(level=logging.INFO,
                                format='%(asctime)s %(levelname)s %(name)s %(message)s')
            self.logger = logging.getLogger(__name__)
        else:
            self.logger = logger
        self.global_state = GlobalState(hostname=dbhost)
        self.buf = self.remap_buf_to_str(buf)
        self.username = self.buf.get('sender')
        if not self.username:
            raise ValueError("No sender in buffer!")
        self.user = self.get_user()
        self.settings = self.get_settings()
        self.statistics = self.get_statistics()

    @classmethod
    def get_schema(cls):
        """
        Returns schema for api doc. Schema should coerce to this format:

        .. code-block:: python

         { "setting_name":
             { "type": "Array", # one of native JSON types
               "required": True, # indicate, should this param being required or not
               "help": "List of whitelisted recipient addresses by given sender(regex)" # help text
             }
         }

        :return: Schema object
        :rtype: dict
        """
        if hasattr(cls.Meta, 'json_fields'):
            return cls.Meta.json_fields
        return {}

    @classmethod
    def get_defaults(cls):
        """
        All subclasses with settings should override this method
        Sets defaults for settings, coercing to following format:

        .. code-block:: python

            { self.name: { "setting1": False, "setting2": True }}
        """
        return {cls.name: {"enabled": False}}

    def get_user(self):
        """
        Get user info from database

        :return: user info
        :rtype: dict
        """
        return self.global_state.get(self.username, {})

    def get_settings(self):
        """
        Get user settings from database

        :return: user settings
        :rtype: dict
        """
        _settings = {'global': config.get_settings_for_plugin(self.__class__.__name__)}
        _settings.update(self.user.get(self.name, {}))
        return _settings

    def update_settings(self):
        """
        Update settings with newer version from database
        """
        self.user = self.get_user()
        self.settings = self.get_settings()

    def save_settings(self):
        """
        Save settings(user settings, statistics) to database
        """
        self.user[self.name] = self.settings
        self.user[self.statistics_name] = self.statistics
        self.global_state[self.username] = self.user
        self.global_state.save()

    def get_checks(self):
        """
        Get all checks for user. Probably this method should be somewhere else.

        :return: list of checks applicable to user
        :rtype: list
        """
        return [k for k in self.user.keys() if k.startswith(self.Meta.prefix + "_")]

    def get_enabled_checks(self):
        """
        Get checks that are enabled for user

        :return: list of enabled checks
        :rtype: list
        """
        checks = {k: self.user.get(k, {}) for k in self.user.keys(
        ) if k.startswith(self.Meta.prefix + "_")}
        checks = [k for k, v in checks.items() if v.get(
            "enabled", False) is True]
        return checks

    def is_enabled(self):
        """
        Is check is enabled

        :return: enabled state
        :rtype: bool
        """
        return self.settings.get('enabled', False)

    @staticmethod
    def remap_buf_to_str(buf):
        """
        Remaps binary buffer to unicode for futher processing

        :param buf: buffer as recv by the wire
        :type buf: dict
        :return: buffer as unicode
        :rtype: dict
        """
        return {k.decode('unicode_escape'): v.decode('unicode_escape') if hasattr(v, 'decode') else v for k, v in
                buf.items()}

    @staticmethod
    def remap_buf_to_bytes(buf):
        """
        Remaps unicode buffer to binary for sending by the wire

        :param buf: buffer as unicode from :func:`~checks.BasicCheck.remap_buf_to_str`
        :type buf: dict
        :return: buffer as bytes
        :rtype: dict
        """
        return {k.encode('unicode_escape'): v.encode('unicode_escape') if hasattr(v, 'encode') else v for k, v in
                buf.items()}

    def check(self):
        """
        Abstract method, all checking process should be there.
        Should return result with one of :func:`~checks.BasicCheck.success_result`
        or :func:`~checks.BasicCheck.failed_result`

        :return: failed or success result
        :rtype: tuple
        """
        raise NotImplementedError(
            "Abstract class doesn't have \"check\" method.")

    def get_statistics(self):
        """
        Returns statistics object for user.
        With rethinkDB store stats for each user is fine, due to map/reduce functionality in rethink.

        :return: stats object
        :rtype: dict
        """
        statistics = self.user.get(self.statistics_name)
        if not statistics:
            statistics = self.default_statistics
        return statistics

    def inc_counter(self, counter, val=1, save=False):
        """
        Increment counter in statistics object

        :param counter: name of the counter
        :type counter: str
        :param val: increment value
        :type val: int
        :param save: controls if save should happen immediately
        """
        counters = self.statistics.get('counters', {})
        counter_val = counters.get(counter, 0) + val
        counters[counter] = counter_val
        if save:
            self.save_settings()

    def get_counters(self):
        """
        Return conters object

        :return: counters object or empty dict if not found
        :rtype: dict
        """
        return self.statistics.get('counters', {})

    def failed_result(self, action=Action.REJECT, reason=''):
        """
        Format failed result with given action and reason

        :param action: Action which sent to postifix
        :type action: :class:`checks.Action`
        :param reason: Reason for rejection
        :type reason: str
        :return: formatted result
        """
        res = (action, reason, False)
        self.logger.debug(
            "Check %s returned result(action, reason, truth): %s", self.name, res)
        return res

    def success_result(self, action=Action.PERMIT, reason=''):
        """
        Format success result with given action and reason

        :param action: Action which sent to postifix
        :type action: :class:`checks.Action`
        :param reason: Reason for accept, doesn't appear in data sent by postfix (may appear in log)
        :type reason: str
        :return: formatted result
        """
        res = (action, reason, True)
        self.logger.debug(
            "Action %s returned result(action, reason, truth): %s", self.name, res)
        return res

    def redirect_result(self, redirect_to):
        """
        Format result for redirect.

        :param redirect_to: email address to which send mail
        :type redirect_to: str
        :return: formatted result
        """
        return self.failed_result(Action.REDIRECT, redirect_to)


class BWListCheck(BasicCheck):
    """Combined black and whitelist check"""

    # @TODO: make ldap `local_only` feature if needed
    # noinspection PyMissingOrEmptyDocstring
    class Meta:
        name = 'bw_list'
        priority = 50
        json_fields = {
            "help": "Combined black and whitelist check separated by sender(first) and recipient",
            "recipient_whitelist": {"type": "Array", "required": True, "help": "List of whitelisted recipient "
                                                                               "addresses by given sender(regex)"},
            "recipient_blacklist": {"type": "Array", "required": True, "help": "List of blacklisted recipient "
                                                                               "addresses by given sender(regex)"},
            "sender_whitelist": {"type": "Array", "required": True, "help": "List of whitelisted sender addresses by "
                                                                            "given recipient(regex)"},
            "sender_blacklist": {"type": "Array", "required": True, "help": "List of blacklisted sender addresses by "
                                                                            "given recipient(regex)"},
            "sender_redirect_to": {"type": "String", "required": False, "help": "If set all blacklisted messages will "
                                                                                "redirect to this address"}
        }

    # noinspection PyMissingOrEmptyDocstring
    @classmethod
    def get_defaults(cls):
        return {cls.name: {
            "recipient_whitelist": [],
            "recipient_blacklist": [],
            "sender_whitelist": [],
            "sender_blacklist": [],
            "sender_redirect_to": None,
            "enabled": False
        }}

    def get_list_for_recipient(self, user, list_type, default=None):
        """
        Helper. Get list from user settings by it type

        :param user:
        :param list_type:
        :param default:
        :return:
        """
        user = self.global_state.get(user, {})
        plugin_settings = user.get(self.name, {})
        return plugin_settings.get(list_type, default)

    def check(self):
        """
        Check four white/black lists for sender/recipient pair and return result.

        **Algorithm**:

        #. Match sender against whitelist
        #. Match sender against blacklist
        #. If no blacklist matches and something matched in whitelist,
           proceed to futher stage, else return failed_result
        #. Match recipient against recipient_whitelist
        #. Match recipient against recipient_blacklist
        #. Return result

        :return: result of check
        :rtype: tuple
        """
        settings = self.settings
        buf = self.buf

        recipient_whitelist = settings.get('recipient_whitelist', ['.*'])
        recipient_blacklist = settings.get('recipient_blacklist', [])
        recipient = buf.get('recipient')
        sender_whitelist = self.get_list_for_recipient(
            recipient, 'sender_whitelist', ['.*'])
        sender_blacklist = self.get_list_for_recipient(
            recipient, 'sender_blacklist', [])
        sender = buf.get('sender')
        permitted = False
        redirect_to = self.get_list_for_recipient(
            recipient, 'sender_redirect_to', None)
        self.logger.warn("Redirect_to set to: %s", redirect_to)

        def check_match(regex, string):
            """Check if regex is actually regular expression and perform string matching(regex or plain text)"""
            try:
                if re.match(regex, string, re.IGNORECASE):
                    return True
            except re.error:
                # Try exact match
                return regex == string

        for regex in sender_whitelist:
            if check_match(regex, sender):
                permitted = True
                break
        for regex in sender_blacklist:
            if check_match(regex, sender):
                permitted = False
                break
        if permitted:
            # if first filter chain permitted, we need to check second filter chain,
            # otherwise there is no need to do that
            for regex in recipient_whitelist:
                if check_match(regex, recipient):
                    permitted = True
                    break
            for regex in recipient_blacklist:
                if check_match(regex, recipient):
                    permitted = False
                    break

        if permitted:
            self.inc_counter('permit', save=True)
            return self.success_result()
        else:
            if redirect_to:
                self.inc_counter('redirect', save=True)
                return self.redirect_result(redirect_to)
            self.inc_counter('reject', save=True)
            return self.failed_result(reason='Rejected by whitelist')
            # else:
            #     # no whitelist, so permit
            #     return success_result(Action.permit)


class StatisticsCollector(BasicCheck):
    """
    Basic plugin for stats collection. Increment counter each time message is sent.
    """

    # noinspection PyMissingOrEmptyDocstring
    class Meta:
        name = "statistics"
        priority = 100
        json_fields = {
            "help": "Basic stats collector, enabled on all users by default. Cannot be disabled"
        }

    def check(self):
        """
        Increment send counter
        :return: success result (dummy)
        """
        send = self.statistics['counters']['send']
        recipient = self.buf.get('recipient')
        stat = send.get(recipient, 0)
        stat += 1
        send[recipient] = stat
        self.save_settings()
        return self.success_result()


class BlockDeliveryForAll(BasicCheck):
    """Plugin for global block delivery for addresses or delivery groups
    For configuration utilises `[BlockDeliveryForAll]` section in config, valid configuration values are:

    * *blocked_addrs* -- json object
    * *key* -- address TO block
    * *value* -- allowed addresses (supports "*" when all addresses are allowed)

    Excludes:
        If you want allow all except one address, you should use following syntax:

        .. code-block:: json

            {
               "my_allowed@example.com":{
                  "allow":[
                     "*"
                  ],
                  "deny":[
                     "joe@example.com"
                  ]
               }
            }
    """

    # noinspection PyMissingOrEmptyDocstring
    class Meta:
        name = "block_CO_delivery"
        priority = 10
        json_fields = {
            "help": "Block sending to CO delivery group"
        }

    def check(self):
        """
        blocked_address format: {"a@example.com": {"allow": ["*"], "deny": []},}
        Ordering hardcoded: ["deny", "allow"]

        .. note:: Only **recipient** check are supported at this time!

        **Algorithm**:

        #. check denied_addrs for wildcard `*`
            #. if wildcard detected - it's special case, so return "Not found" (if all users are denied
               to mail this sender, no one can find it )
        #. check if sender in allowed_addrs or wildcard `*` in there:
            #. check denied_addrs
        #. return result of prev. operations

        :return: result of checking
        :rtype: tuple
        """
        global_settings = self.settings['global']  # just a shortcut
        recipient = self.buf.get('recipient')
        sender = self.buf.get('sender')
        if not global_settings:
            self.logger.warning("plugin \"%s\" has no global settings! No blocking can be perfomed",
                                self.__class__.__name__)
        try:
            blocked_addrs = json.loads(global_settings.get('blocked_addrs', '{}'))
        except ValueError:
            blocked_addrs = {}
            self.logger.error("""Cannot load "blocked_addrs" from config file.
                              Check JSON syntax with linter and try again!""")

        if recipient in blocked_addrs.keys():
            addrs = blocked_addrs.get(recipient)
            allowed_addrs = addrs.get("allow", [])
            denied_addrs = addrs.get("deny", [])

            self.logger.debug("result for recipient %s: %s(allowed: %s, deny: %s)", recipient,
                              "deny" if (sender not in allowed_addrs or '*' not in allowed_addrs) else "allow",
                              allowed_addrs, blocked_addrs
                              )
            if '*' in denied_addrs:
                self.logger.info("Wildcard found in list of denied addresses. It's strange, but we're still\
block and reply with unknown user")
                return self.failed_result(reason="User unknown in local recipient table")

            if sender not in allowed_addrs or '*' not in allowed_addrs:
                # special case for allow all, block one
                if sender in denied_addrs:
                    return self.failed_result(reason="This address is blocked for you. Sorry.")
                if '*' in allowed_addrs:
                    self.logger.debug("Wildcard found, allow")
                return self.success_result()
        return self.success_result()


class RateLimitCheck(BasicCheck):
    """Basic rate limiting class. Currently doesn't support per-recipient rate-limit"""

    # noinspection PyMissingOrEmptyDocstring
    class Meta:
        name = 'rate_limit'
        priority = 40
        json_fields = {
            "help": "Basic rate limiting check. Limit per sender, currently doesn't support per-recipient rate-limit",
            "maxcount": {"type": "Number", "required": True, "help": "Maximum count of sended messages"},
            "ttl": {"type": "Number", "required": True, "help": "Rate in seconds, see maxcount"},
        }

    ttl = 3600
    maxcount = 50

    # noinspection PyMissingOrEmptyDocstring
    @classmethod
    def get_defaults(cls):
        return {cls.name: {
            "maxcount": cls.maxcount,
            "ttl": cls.ttl,
            "enabled": False
        }}

    def check(self):
        """
        Rate-limiting with TTL.
        :return: result of checking
        """
        settings = self.settings

        def parse_int(v, default=0):
            """ Convert value to int, if failed return default"""
            try:
                return int(v)
            except (ValueError, TypeError):
                return default

        def renew_age():
            """Renew TTL"""
            maxcount = parse_int(settings.get('maxcount'), self.maxcount)
            ttl = parse_int(settings.get('ttl'), self.ttl)
            now_time = time.time()
            until = now_time + ttl
            settings['count'] = 0
            settings['maxcount'] = maxcount
            settings['ttl'] = ttl
            settings['now_time'] = now_time
            settings['until'] = until

            self.save_settings()

        if not settings:
            renew_age()

        if time.time() > settings['until']:
            renew_age()

        stop = settings['count'] >= settings['maxcount']
        if stop:
            return self.failed_result(reason='Rate-limit exceeded')
        else:
            settings['count'] += 1
            self.save_settings()
            return self.success_result()


class BasicAddressCheck(BasicCheck):
    """Perform checking recipients. For testing purposes only. Now not only ASCII addresses can be.
    So check is more or less obsolete"""

    # noinspection PyMissingOrEmptyDocstring
    class Meta:
        name = 'basic_addr'
        priority = 60
        json_fields = {
            "help": "Perform basic address correctness check(ensure ASCII)"
        }

    def check(self):
        """
        Check if string is ASCII

        :return result of operation
        """
        def is_ascii(s):
            """Detect if string is ASCII"""
            try:
                s.encode('ascii')
                return True
            except UnicodeEncodeError:
                return False

        buf = self.buf
        dst = buf.get('recipient')
        src = buf.get('sender')
        if not (src and dst):
            return self.failed_result(reason='No src or dst!')
        if is_ascii(src) and is_ascii(dst):
            return self.success_result(reason='Address contains only ASCII characters')
        else:
            return self.failed_result(reason='Address can contain only ASCII characters')


class RandomCheck(BasicCheck):
    """Block sender from send a message. *Randomly*"""

    # noinspection PyMissingOrEmptyDocstring
    class Meta:
        name = 'random'
        priority = 70
        json_fields = {
            "help": "Just random things. Like guessing on the camomile"
        }

    def check(self):
        """With change `1/10` reject a message"""
        import random
        if random.randint(0, 100) % 10 == 0:
            return self.failed_result(reason='Random said you\'re loser!')
        else:
            return self.success_result('You can pass')


class _Checks(Enum):
    """
    Storage class for all available checks. Generated by :func:`~checks.generate_checks_enum`
    """
    @classmethod
    def get(cls, val):
        """:return value from Enum"""
        return cls.__dict__.get(val).value


def generate_checks_enum():
    """
    Generate checks from globals.
    Improve this method if you want loading from other sources, or see :func:`utils.load_class`
    :return: all discovered checks
    :rtype: :class:`checks._Checks`
    """
    names = {}
    for k, v in list(globals().items()):
        try:
            if issubclass(v, BasicCheck):
                names[v.name] = v
        except TypeError:
            pass

    # noinspection PyArgumentList
    # names are initializer for enum
    return _Checks('Checks', names)


Checks = generate_checks_enum()
