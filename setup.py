from setuptools import setup

setup(
    install_requires=[
        "PyZMQ~=19.0",
        "schema~=0.7.2",
        "toml~=0.10",
        "sqlalchemy",
        "dnspython",
        "quart",
        "flask-sqlalchemy",
    ]
)
