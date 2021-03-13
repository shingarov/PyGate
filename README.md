# PyGate
PyGate allows use of Python libraries from Smalltalk.

## Installation
Load PyGate into your Pharo image:
```
Metacello new
  baseline: 'PyGate';
  repository: 'github://shingarov/PyGate:ghost';
  load
```
Launch the TCP server at
`.../pharo-local/iceberg/PyGate/py/gate.py`
