# msfenum

# Installing
To get up and running, install directly from Github into a python virtualenv:
```bash
$ virtualenv --python=python3 msfenum
$ source msfenum/bin/activate
$ pip install git+https://github.com/r1tger/msfenum
$ msfenum --help
```

# Using
Once installed, call ```msfenum``` with the ```--help``` parameter.

# Developing
If you'd like to contribute to development of msfenum, set up a development
environment:
```bash
$ git clone https://github.com/r1tger/msfenum
$ cd msfenum
$ virtualenv --python=python3 env
$ source env/bin/activate
$ pip install --editable .
```
Now edit any files in the msfenum/ package and submit a pull request.

# TO-DO
* Add documentation
* Add test cases
