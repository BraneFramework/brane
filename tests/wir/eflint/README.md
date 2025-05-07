# eFLINT Test Cases for WIR -> eFLINT compiler

This folder contains the "golden" answers for the compilation from WIR files to eFLINT.

Note that, typically, the compilation from WIR -> Workflow (which happens first) is very lossy; only interesting things like branches, loops and task calls are kept.

Further, this process attempts to eliminate any BraneScript function calls, as these are not supported by the Workflow.

As such, the following WIR files are not supported:
- `class.json` is not supported because the analysis can't extract the called function from projection; and
- `recursion.json` because recursive functions cannot be inlined.

The first one can be solved by implementing a more complex analysis algorithm that extracts called function IDs based on stack emulation instead of the "looking at the previous instruction and guessing"-kind of analysis. But that's a TODO.
