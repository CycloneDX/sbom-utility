# Example 5

## Description

```
content
├── build
│   └── hello
└── src
    ├── Makefile
    └── hello.go
```

The content is identical to [example2](../example2), but in Go instead of C: one [Go source file](content/src/hello.go) with a simple "hello world" program, compiled into a [single binary](content/build/hello) with no dependencies via a [Makefile](content/src/Makefile).

## Comments

This is intentionally a trivial example, and the SPDX files are essentially identical to those of [example2](../example2).
Subsequent examples will build upon this to add more detail to this simple case.
