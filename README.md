IEEE Symposium on Security and Privacy 2026 open science artifacts submission

This is a repository of all artifacts associated with our CHERI-D paper submission. It contains copies of our source code for our CHERI-enabled LLVM and QEMU fork, CheriBSD fork and CHERI-Toooba that has CHERI-D hardware, and software CHERI-D support implementations. It also contains a list of Juliet Test Cases we have run.

## Relevant Files
### CHERI-Toooba: 
- `Toooba/src_Core/RISCY_OOO/procs`, contains the implementations of CHERI-D related instructions, ID buffer and ID detection logic on both load and store. 
- `Toooba/libs/cheri-cap-lib`, contains the implementation of CHERI-D changes to CHERI capability format

### QEMU: 
- `qemu/target/cheri-common/`,  contains the implementation of CHERI-D extended CHERI capability format, CHERI-D added instructions and check on memory access

### CheriBSD: 
- `cheribsd/lib/libc/stdlib/malloc/mrs`, contains the implementation of CHERI-D enforcement on allocation, e.g., inline-ID and in-page ID operations, fences instructions to flush ID buffer on ID updates.
- `cheribsd/sys/vm/`, `cheribsd/sys/riscv/riscv/`, `cheribsd/sys/kern/kern_cheri_revoke.c`, contains the implementation of CHERI-D kernel ID revoker.

### LLVM:
- `llvm-project/llvm/lib/Target/RISCV/RISCVInstrInfoXCheri.td`, contains the assembler support for CHERI-D support instructions. 

### Juliet-Test-Suite: 
The tests we used for security evaluations are placed in `juliet-test-suite-c/bin`
## Omissions

This repository is intended to be anonymized via <https://anonymous.4open.science>, which has a 2GB-per-user limit.
To avoid this limit we have removed the following irrelevant, redundant, or binary files:

- directories from `cheribsd/contrib` took up ~650MB of source files unrelated to PoisonCap
- `cheribsd/sys/contrib` took up ~370MB of source files unrelated to PoisonCap
- `qemu/roms` took up ~660MB and contained binary boot ROMs unrelated to PoisonCap

We have also removed `*.git*` files throughout.

