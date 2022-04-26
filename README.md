# testxmpp

A re-implementation of the original [xmppoke](https://github.com/xmpp-observatory/xmppoke/)-based XMPP observatory in Python, based on [testssl.sh](https://testssl.sh).

Currently, this isn't quite ready for the stage yet, but if you want to play, you should be able to get quite far with `docker-compose up` and then navigating to `http://localhost:8000`. If your user ID is not 1000, you might have to change the docker-compose file so that it can read/write the testing SQLite database.
