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
        "Quart~=0.13",
        "Flask-SQLAlchemy~=2.4",
        "environ-config~=20.1",
    ],
    include_package_data=True,
)
