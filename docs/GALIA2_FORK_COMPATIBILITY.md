# GALIA 2.0 fork compatibility rebase

Target repository: `riosriosje-prog/test-model-thing`

Baseline fork `main` commit at rebase: `fa27663a5dded4f83c93abbf3890d14a66139e09`.

Pinned Legacy `main.py` Git blob: `715b9be844284f13eb885e3301c90c5a04b3c6bc`.

The GALIA 2.0 overlay remains add-only. The fork Legacy runtime is not replaced or edited. Connector-side AST contract verification confirmed that `Runtime.__init__`, `save`, `call`, `write`, `chat`, `train`, `now`, and `__call__` retain the P10-observed surface; `Runtime.call` delegates to `self.model(c, n, end, frozen)`, gates `self.save()` on `save`, returns `outputs`, and retains the `__main__` guard.

This rebase changes only the repository-integration anchor used by the verifier and its corresponding test expectation. It does not grant authority, promote canonical state, or alter Legacy execution.
