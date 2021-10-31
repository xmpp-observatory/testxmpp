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
            "Quart~=0.13",
            "Flask-SQLAlchemy~=2.4",
            "Flask-Babel~=2.0",
            "Flask-WTF~=0.14",
        ],
        'xmpp': [
            "aioxmpp~=0.11",
        ],
        'testssl': [
        ],
        'coordinator': [
            "aioxmpp~=0.11",
        ],
    },
    include_package_data=True,
)
