from setuptools import setup

setup(
    name='msfenum',
    version='0.1.0',
    description='Make enumeration great again',
    url='https://github.com/r1tger/msfenum',
    author='Ritger Teunissen',
    author_email='github@ritger.nl',
    packages=['msfenum'],
    # setup_requires=['pytest-runner'],
    # tests_require=['pytest>=3.0.0', 'freezegun'],
    install_requires=[
        'jinja2',
        'msgpack',
        'requests',
        'toml'
    ],
    entry_points={'console_scripts': [
        'msfenum = msfenum.__main__:main',
    ]},
    zip_safe=False
)
