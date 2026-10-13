# Tests

The kit is tested on synthetic programs written for this purpose
(`fixtures/dos/src/`, a small "engine" with function-pointer tables, varargs,
a no-return error handler, a switch, 64-bit math, a heap-allocated global
struct). No game binaries or game code are used or stored here.

```
python tests/build_fixtures.py                # needs Open Watcom ($WATCOM), dev/CI only
python tests/run_tests.py -v                  # build + retrokit analyze + score + compare with baseline.json
python tests/run_tests.py --no-build --no-analyze   # re-score existing results
python tests/run_tests.py --update-baseline   # accept the current scores
python -m unittest discover -s tests          # tools, formats, CLI (no Ghidra)
```

Variants (`build_fixtures.py`): stack (`-5s`) and register (`-5r`) convention,
DOS/4GW, DOS32A and PMODE/W stubs, optimized (`-oneatx`) and unoptimized (`-od`), and a
Win32 PE (`nt_s`) for the PE pipeline. `retrokit analyze` runs with automatic detection; the
detected calling convention must match the one the variant was compiled with.
The linker map (`engine.map`) gives the address and module of every function;
`evaluate.py` scores the export against it and against the sources:

| metric | meaning |
|---|---|
| `own`, `lib` | functions found at exactly the right address (fixture code / Watcom runtime) |
| `own_params` | fixture functions whose exported signature has the right number of parameters |
| `calls_args` | calls between fixture functions passing the right number of arguments |
| `strings` | string literals of the sources printed as `"..."` in the decompiled C |
| `own_truncated` | fixture functions whose body Ghidra cut short |
| `extraout`, `unaff`, `undefined8`, `in_reg`, `warnings` | noise in the decompiled C (lower is better) |

Annotations in the sources (comment line before a function): `@noreturn`,
`@table` (only reachable through a pointer table), `@varargs`.

To tune the pipeline on real binaries you own, keep them outside the repository.
