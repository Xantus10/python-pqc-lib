# Package structure

The package is structured into two modules:

```
python_pqc_lib
  - kem
  - dsa
```

You should only ever include classes and functions from these modules.

`python_pqc_lib.kem`

`python_pqc_lib.dsa`

Other forms of import may not work.

There are also a few helper objects in `python_pqc_lib.util` package.
