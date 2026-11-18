from setuptools import setup, find_packages

setup(
    name="testxmpp",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "PyZMQ>=25,<27",
        "schema~=0.7.2",
        "sqlalchemy~=1.3",
        "dnspython~=2.0",
        "environ-config~=20.1",
        "aiohttp",
        "defusedxml",
        'pyasn1',
        'pyasn1_modules',
        'alembic==1.7.5',
        'flask==1.1.4',
        'flask_sqlalchemy==2.5.1',
        'flask_migrate==3.1.0',
        'gunicorn==20.1.0',
        'requests==2.26.0',
        'pytest==6.2.5',
        'pytest-cov==2.12.1',
        'pytz==2021.3',
        'quart==0.14.1',  # Ensure the correct version of quart is installed
        'jinja2==2.11.3',
        'markupsafe==1.1.1'
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
