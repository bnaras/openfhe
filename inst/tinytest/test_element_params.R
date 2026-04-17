## R-SPECIFIC: ElementParams S7 class scaffolding
## Block E 9101 ships the class definition only. Full constructor path
## (via get_element_params(cc), params arg on make_ckks_packed_plaintext)
## lands at 9100.2 / 9105 respectively.
library(openfhe)

# ── Class hierarchy ─────────────────────────────────────
expect_true(S7::S7_inherits(ElementParams(ptr = NULL), ElementParams))
expect_true(S7::S7_inherits(ElementParams(ptr = NULL), OpenFHEObject))

# ── Null-pointer construction + print path ──────────────
## ElementParams at 9101 has no constructor path from R (no
## get_element_params helper until 9100.2). The scaffolding test
## confirms only that the class object constructs with ptr = NULL
## and that print does not error. Richer tests land at 9100.2 once
## there is a real pointer source.
ep_null <- ElementParams(ptr = NULL)
expect_false(openfhe:::ptr_is_valid(ep_null))
## print returns the object invisibly; verify it does not throw
expect_silent(invisible(capture.output(print(ep_null))))
expect_identical(invisible(print(ep_null)), ep_null)
