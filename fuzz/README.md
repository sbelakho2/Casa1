# Casa1 Fuzz Targets

Run the PE parser target with cargo-fuzz:

```sh
cargo fuzz run pe_parser -- -runs=1000
```

The target asserts two properties for each input:

- no parser crash or panic
- deterministic summary for identical input bytes