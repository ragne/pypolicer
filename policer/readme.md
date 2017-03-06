### Postfix sender\recipient restrictions plugin (pypolicer)
This is a standalone software that performs policing based on rules, that stored in config file or database

### Currently supported databases:
 - RethinkDB

### What is supported:
 - Blacklist\whitelist plugin
 - Basic address check (for RFC-compilance, but Unicode is not supported yet, sorry)
 - Blocking delivery based on global config settings
 - Collecting statistics
 - Config live-reload

### Installations
**prerequirements**:
  - Make a virtualenv
  - Install rethinkDB from https://www.rethinkdb.com/docs/install/
  - Clone this repository via git
  - Install requirements.txt `pip install -r requirements.txt`


**Sample config file `policer.conf` has commentary, that explains every setting. Please check it before starting a daemon!**

Edit postfix main.cf and add this line:
 `smtpd_recipient_restrictions = check_policy_service { inet:127.0.0.1:16000, timeout=10s, default_action=DUNNO}, permit`

By default `policer` server listening on `127.0.0.1:16000`, but it can be altered via command line arguments or config file.

Run software in daemon mode with: `python -m policer start -c policer.conf`

Stop daemon with: `python -m policer stop`

For help: `python -m policer -h`


### Documentation

Generate via sphinx from docstrings:
    - To be documented

Hosted version: https://lain.im/policer/policer.html


### Warning
This is not actively maintained project. Basically I developed it for one task, we need to perform on my work.
It was worth one blog post about postfix and milters(but currently I have no time for it, maybe later).

Anyway, milters are more capable of limiting and filtering by content, but this approach is simplier.
