
# YosysHQ License Checker

To build license checker tool and static library
```
cmake .
make -j
```

To build tests and get coverage report

```
cmake -DBUILD_TESTS=ON -DCODE_COVERAGE=ON -DCMAKE_BUILD_TYPE=Debug .
make -j
make coverage
```
