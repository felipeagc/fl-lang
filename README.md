# Fl-lang

A systems programming language based on LLVM, with a focus on both high performance and convenience.

Example code (more examples in the [examples](https://github.com/felipeagc/fl-lang/tree/master/examples) folder):

```go
module main

import "core:c"

func main() {
    c.printf(c"Hello, world: %d!\n");
}
```

## Building

### Linux
To build the compiler on linux just run `make` on the project root.
