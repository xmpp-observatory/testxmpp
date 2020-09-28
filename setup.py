from setuptools import setup, find_packages

setup(
    name="testxmpp",
    version="0.0.1",
    packages=find_packages(),
    install_requires=[
        "PyZMQ~=19.0",
        "schema~=0.7.2",
        "sqlalchemy",
        "dnspython",
        "quart",
        "flask-sqlalchemy",
        "environ-config~=20.1",
    ],
    include_package_data=True,
)
