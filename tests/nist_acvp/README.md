# Notice

This directory contains tests which utilize a subset of the data from [NIST ACVP project](https://github.com/usnistgov/ACVP-Server/tree/master). This data is not part of my original work and the license is availible under `NIST_LICENSE`.

Data that is sourced from the project is marked with a python comment stating `NIST ACVP` directly above the variable. Files that contain data sourced from the project are prepended with a `nist_`.

Example in python code:

```python
# NIST ACVP
keygen_test_values = [...]
```

Example in filename:

`nist_test_keygen_512.json`
