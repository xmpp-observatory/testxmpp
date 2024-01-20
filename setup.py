from setuptools import setup, find_packages

setup(
    name="testxmpp",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "PyZMQ~=19.0",
        "schema~=0.7.2",
        "sqlalchemy~=1.3",
        "dnspython~=2.0",
        "environ-config~=20.1",
        "aiohttp",
        "defusedxml",
        'pyasn1',
        'pyasn1_modules',
    ],
    extras_require={
        'web': [
            "Quart~=0.18,<0.19",
            "Flask-SQLAlchemy~=3.0",
            "Flask-Babel~=2.0,<3.0",
            "Flask-WTF~=1.1,<1.2",
            "werkzeug~=2.2,<3",
        ],
        'xmpp': [
            "aioxmpp~=0.11",
        ],
        'testssl': [
        ],
        'coordinator': [
            "aioxmpp~=0.11",
            "pytz",
        ],
    },
    include_package_data=True,
)
