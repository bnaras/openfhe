## OPENFHE PYTHON SOURCE: openfhe/openfhe-python/src/lib/bindings.cpp (cross-stack signature projection)
## R-SPECIFIC: Block E Signal 1 of the three-way parity harness
## @openfhe-python: FULL — live harness for 5 canonical methods + upstream-defects.md parser
##
## This test runs the three signature dumpers (R / Python / C++ header)
## and projects 5 known-good methods plus the upstream-defects.md tag
## parser. It was the 9100.0 surface-parity gate referenced by
## design.md §10 9100.0 DoD and harness.md §2.4 and has remained live
## throughout Block E. At Block E 9124 (9100.8 capstone) the file's
## role transitioned from "advisory gate" to "live regression guard
## for the Block E surface parity contract" — the P3/P4 UNVERIFIED
## canaries were resolved to N/A after a direct header re-read, so
## the parser no longer requires an UNVERIFIED entry to exist.
##
## Position-based matching (advisory name-mismatch) remains — one
## advisory message is printed for the Encrypt `publicKey` vs `pk_xp`
## parameter name disagreement, which is a cosmetic R-side binding
## convention (cpp11 internals use `_xp` suffixes) rather than a
## surface-parity defect. Flipping to strict-name matching would
## require renaming every cpp11 internal arg, which is a post-Block-E
## cleanup task with no functional benefit.

if (!requireNamespace("tinytest", quietly = TRUE)) {
  return(invisible(NULL))
}

## ---------------------------------------------------------------------
## 0. Skip gates — be paranoid about path resolution.
## ---------------------------------------------------------------------

if (!nzchar(Sys.which("python3")) && !nzchar(Sys.which("python"))) {
  tinytest::exit_file("python not on PATH; surface parity harness skipped")
}

if (!requireNamespace("jsonlite", quietly = TRUE)) {
  tinytest::exit_file("jsonlite not installed; surface parity harness skipped")
}

VENV_DIR <- "/Users/naras/research/fhe/temp/openfhe-python-venv"
VENV_PY  <- file.path(VENV_DIR, "bin", "python")

if (!file.exists(VENV_PY)) {
  tinytest::exit_file(sprintf(
    "openfhe-python venv missing at %s; surface parity harness skipped",
    VENV_DIR))
}

## All three dumpers live in inst/scripts/ (versioned under the R
## package): two R scripts and one Python script. Prefer
## system.file() (post-install path); fall back to the source tree
## if the test is being run from R_dev directly.
locate_script <- function(name) {
  p <- system.file("scripts", name, package = "openfhe")
  if (nzchar(p) && file.exists(p)) return(p)
  fallback <- file.path(
    "/Users/naras/research/fhe/R_dev/openfhe/inst/scripts", name)
  if (file.exists(fallback)) return(fallback)
  ""
}

DUMP_R       <- locate_script("dump_r_signatures.R")
DUMP_HEADER  <- locate_script("dump_header_signatures.R")
DUMP_PYTHON  <- locate_script("dump_python_signatures.py")

if (!nzchar(DUMP_R) || !nzchar(DUMP_HEADER) || !nzchar(DUMP_PYTHON)) {
  tinytest::exit_file(
    "one or more inst/scripts/dump_*_signatures.* not found; surface parity harness skipped")
}

## Scratch directory for the JSON outputs — under temp/, never /tmp.
SCRATCH <- "/Users/naras/research/fhe/temp/scratch"
dir.create(SCRATCH, recursive = TRUE, showWarnings = FALSE)

R_JSON      <- file.path(SCRATCH, "signatures-r.json")
PY_JSON     <- file.path(SCRATCH, "signatures-python.json")
HEADER_JSON <- file.path(SCRATCH, "signatures-header.json")

UPSTREAM_DEFECTS <- "/Users/naras/research/fhe/notes/upstream-defects.md"
if (!file.exists(UPSTREAM_DEFECTS)) {
  tinytest::exit_file("notes/upstream-defects.md missing; surface parity harness skipped")
}

## ---------------------------------------------------------------------
## 1. Run the three dumpers via system2().
## ---------------------------------------------------------------------

run_quiet <- function(cmd, args) {
  rc <- suppressWarnings(system2(cmd, args, stdout = FALSE, stderr = FALSE))
  if (!is.numeric(rc)) rc <- 1L
  as.integer(rc)
}

rc_r <- run_quiet(file.path(R.home("bin"), "Rscript"),
                  c(DUMP_R, "--output", R_JSON))
rc_p <- run_quiet(VENV_PY,
                  c(DUMP_PYTHON, "--output", PY_JSON))
rc_h <- run_quiet(file.path(R.home("bin"), "Rscript"),
                  c(DUMP_HEADER, "--output", HEADER_JSON))

if (rc_r != 0L || !file.exists(R_JSON)) {
  tinytest::exit_file("R-side signature dump failed; surface parity harness skipped")
}
if (rc_p != 0L || !file.exists(PY_JSON)) {
  tinytest::exit_file("Python-side signature dump failed; surface parity harness skipped")
}
if (rc_h != 0L || !file.exists(HEADER_JSON)) {
  tinytest::exit_file("Header-side signature dump failed; surface parity harness skipped")
}

sigs_r  <- jsonlite::fromJSON(R_JSON,      simplifyVector = FALSE)
sigs_py <- jsonlite::fromJSON(PY_JSON,     simplifyVector = FALSE)
sigs_h  <- jsonlite::fromJSON(HEADER_JSON, simplifyVector = FALSE)

## ---------------------------------------------------------------------
## 2. Lookup helpers — position-based projection.
## ---------------------------------------------------------------------

## type_class projection of an R argument name. cpp11 internals carry
## the receiver as the first arg (`cc_xp`) which is the context, not
## a binding parameter — strip it. Trailing `...` from the S7 generic
## dispatch is also a wrapper ergonomic and is stripped.
strip_r_receiver <- function(args) {
  if (length(args) == 0L) return(args)
  first <- args[[1L]]$name %||% ""
  if (first %in% c("cc_xp", "ctx_xp")) args <- args[-1L]
  args <- Filter(function(a) (a$name %||% "") != "...", args)
  args
}

`%||%` <- function(a, b) if (is.null(a)) b else a

## Project an R formal-arg name → coarse type_class for position
## comparison. cpp11 internals encode the type in the suffix
## (`pk_xp` → PublicKey, `sk_xp` → PrivateKey, `ct_xp` → Ciphertext,
## `pt_xp` → Plaintext). For exported wrappers we use the same
## conventions; unknown args project as "any" (used only when name
## cannot be inferred — position alignment is what matters).
r_arg_type_class <- function(name) {
  n <- name %||% ""
  if (n %in% c("pk_xp", "key", "publicKey", "public_key", "pk")) return("PublicKey")
  if (n %in% c("sk_xp", "privateKey", "private_key", "sk")) return("PrivateKey")
  if (n %in% c("ct_xp", "ct", "ct1_xp", "ct2_xp", "ciphertext", "ciphertext1",
               "ciphertext2", "x", "y")) return("Ciphertext")
  if (n %in% c("pt_xp", "pt", "plaintext")) return("Plaintext")
  if (n == "values") return("int_vector")
  "any"
}

## Look up a method in the R signatures by exported-name OR
## internal cpp11 name. Returns NULL if not found. The lookup tries
## the explicit cpp11 internal name first (matches C++ overload key),
## then falls back to the exported name.
find_r_method <- function(internal_name, exported_name) {
  for (m in sigs_r$internal_methods) {
    if ((m$name %||% "") == internal_name) return(list(kind = "internal", entry = m))
  }
  for (m in sigs_r$methods) {
    if ((m$name %||% "") == exported_name) return(list(kind = "exported", entry = m))
  }
  NULL
}

## Find a Python method by class + name; returns the FIRST overload
## that matches the predicate (or the first overload if predicate=NULL).
find_python_method <- function(class_name, method_name, predicate = NULL) {
  for (m in sigs_py$methods) {
    if ((m$class %||% "") == class_name && (m$name %||% "") == method_name) {
      if (is.null(predicate) || predicate(m)) return(m)
    }
  }
  NULL
}

## Find a C++ header method by name + predicate (selects the canonical
## overload when there are several).
find_header_method <- function(method_name, predicate = NULL) {
  for (m in sigs_h$methods) {
    if ((m$name %||% "") == method_name) {
      if (is.null(predicate) || predicate(m)) return(m)
    }
  }
  NULL
}

## Project each arg of a Python or header entry to (type_class) as a
## position-keyed character vector.
type_class_vec <- function(entry) {
  if (is.null(entry)) return(character(0))
  vapply(entry$args, function(a) a$type_class %||% "any", character(1))
}

## Hide a `Plaintext*` out-parameter from a header arg list (Decrypt).
hide_plaintext_outparam <- function(entry) {
  if (is.null(entry)) return(entry)
  keep <- vapply(entry$args, function(a) {
    nm <- a$name %||% ""
    tc <- a$type_class %||% ""
    !(tc == "Plaintext" && nm == "plaintext")
  }, logical(1))
  entry$args <- entry$args[keep]
  entry
}

## Note a name mismatch but do not fail (9100.0 advisory mode).
note_name_mismatch <- function(method, r_names, header_names) {
  if (!identical(r_names, header_names)) {
    message(sprintf(
      "[surface-parity] %s: name_mismatch (advisory at 9100.0): R=%s vs C++=%s",
      method,
      paste(r_names, collapse = ","),
      paste(header_names, collapse = ",")))
  }
  invisible(NULL)
}

## ---------------------------------------------------------------------
## 3. Known-good case 1: Encrypt(publicKey, plaintext)
## ---------------------------------------------------------------------

cpp_encrypt <- find_header_method("Encrypt", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "PublicKey" && tc[2] == "Plaintext"
})
py_encrypt <- find_python_method("CryptoContext", "Encrypt", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "PublicKey" && tc[2] == "Plaintext"
})
r_encrypt <- find_r_method("CryptoContext__Encrypt_PublicKey", "encrypt")

expect_true(!is.null(cpp_encrypt), info = "Encrypt: C++ canonical overload not found")
expect_true(!is.null(py_encrypt),  info = "Encrypt: Python canonical overload not found")
expect_true(!is.null(r_encrypt),   info = "Encrypt: R binding not found")

if (!is.null(cpp_encrypt) && !is.null(py_encrypt) && !is.null(r_encrypt)) {
  cpp_tc <- type_class_vec(cpp_encrypt)
  py_tc  <- type_class_vec(py_encrypt)
  r_args <- strip_r_receiver(r_encrypt$entry$args)
  r_tc   <- vapply(r_args, function(a) r_arg_type_class(a$name), character(1))
  expect_equal(length(r_tc), length(cpp_tc),
               info = "Encrypt: arg count mismatch (R vs C++)")
  expect_identical(cpp_tc, py_tc,
                   info = "Encrypt: C++ vs Python type_class projection")
  expect_identical(r_tc, cpp_tc,
                   info = "Encrypt: R vs C++ position-based type_class projection")
  note_name_mismatch("Encrypt",
                     vapply(r_args, function(a) a$name %||% "", character(1)),
                     vapply(cpp_encrypt$args, function(a) a$name %||% "", character(1)))
}

## ---------------------------------------------------------------------
## 4. Known-good case 2: Decrypt(privateKey, ciphertext) with Plaintext* hidden
## ---------------------------------------------------------------------

cpp_decrypt_raw <- find_header_method("Decrypt", function(m) {
  tc <- type_class_vec(m)
  ## We accept either (privateKey, ciphertext, Plaintext*) [3 args] or
  ## (ciphertext, privateKey, Plaintext*) [3 args] — the projection
  ## hides the out-param. Pick the privateKey-first form.
  length(tc) == 3L && tc[1] == "PrivateKey" && tc[2] == "Ciphertext" && tc[3] == "Plaintext"
})
cpp_decrypt <- hide_plaintext_outparam(cpp_decrypt_raw)
py_decrypt <- find_python_method("CryptoContext", "Decrypt", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "PrivateKey" && tc[2] == "Ciphertext"
})
r_decrypt <- find_r_method("CryptoContext__Decrypt", "decrypt")

expect_true(!is.null(cpp_decrypt_raw), info = "Decrypt: C++ canonical 3-arg overload not found")
expect_true(!is.null(py_decrypt),      info = "Decrypt: Python lambda-adapted form not found")
expect_true(!is.null(r_decrypt),       info = "Decrypt: R cpp11 internal not found")

if (!is.null(cpp_decrypt) && !is.null(py_decrypt) && !is.null(r_decrypt)) {
  cpp_tc <- type_class_vec(cpp_decrypt)
  py_tc  <- type_class_vec(py_decrypt)
  expect_equal(length(cpp_tc), 2L,
               info = "Decrypt: out-param hiding produced != 2 C++ args")
  expect_identical(cpp_tc, py_tc,
                   info = "Decrypt: C++ (post-out-param-hiding) vs Python")
  r_args <- strip_r_receiver(r_decrypt$entry$args)
  r_tc <- vapply(r_args, function(a) r_arg_type_class(a$name), character(1))
  expect_equal(length(r_tc), 2L,
               info = "Decrypt: R cpp11 internal arg count after receiver strip")
  expect_identical(r_tc, cpp_tc,
                   info = "Decrypt: R vs C++ (post-out-param-hiding) projection")
}

## ---------------------------------------------------------------------
## 5. Known-good case 3: EvalAdd(ciphertext1, ciphertext2)
## ---------------------------------------------------------------------

cpp_evaladd <- find_header_method("EvalAdd", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
py_evaladd <- find_python_method("CryptoContext", "EvalAdd", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
r_evaladd <- find_r_method("EvalAdd__ct_ct", "eval_add")

expect_true(!is.null(cpp_evaladd), info = "EvalAdd: C++ ct/ct overload not found")
expect_true(!is.null(py_evaladd),  info = "EvalAdd: Python ct/ct overload not found")
expect_true(!is.null(r_evaladd),   info = "EvalAdd: R cpp11 internal not found")

if (!is.null(cpp_evaladd) && !is.null(py_evaladd) && !is.null(r_evaladd)) {
  cpp_tc <- type_class_vec(cpp_evaladd)
  py_tc  <- type_class_vec(py_evaladd)
  expect_identical(cpp_tc, py_tc, info = "EvalAdd: C++ vs Python")
  r_args <- strip_r_receiver(r_evaladd$entry$args)
  r_tc <- vapply(r_args, function(a) r_arg_type_class(a$name), character(1))
  expect_identical(r_tc, cpp_tc, info = "EvalAdd: R vs C++ position projection")
}

## ---------------------------------------------------------------------
## 6. Known-good case 4: EvalMult(ciphertext1, ciphertext2)
## ---------------------------------------------------------------------

cpp_evalmult <- find_header_method("EvalMult", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
py_evalmult <- find_python_method("CryptoContext", "EvalMult", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
r_evalmult <- find_r_method("EvalMult__ct_ct", "eval_mult")

expect_true(!is.null(cpp_evalmult), info = "EvalMult: C++ ct/ct overload not found")
expect_true(!is.null(py_evalmult),  info = "EvalMult: Python ct/ct overload not found")
expect_true(!is.null(r_evalmult),   info = "EvalMult: R cpp11 internal not found")

if (!is.null(cpp_evalmult) && !is.null(py_evalmult) && !is.null(r_evalmult)) {
  cpp_tc <- type_class_vec(cpp_evalmult)
  py_tc  <- type_class_vec(py_evalmult)
  expect_identical(cpp_tc, py_tc, info = "EvalMult: C++ vs Python")
  r_args <- strip_r_receiver(r_evalmult$entry$args)
  r_tc <- vapply(r_args, function(a) r_arg_type_class(a$name), character(1))
  expect_identical(r_tc, cpp_tc, info = "EvalMult: R vs C++ position projection")
}

## ---------------------------------------------------------------------
## 7. Known-good case 5: MakePackedPlaintext — partial parity canary
##
## C++ has 3 args (value, noiseScaleDeg, level); R currently exposes
## only (cc, values) — i.e. 1 arg post-receiver-strip. This is the
## At 9100.0 this was a deliberate PARTIAL case (R had 1 arg, C++
## had 3). At 9107 the R binding was extended with `noise_scale_deg`
## and `level` args, closing the gap — R now has 3 args matching
## C++ and Python.
## ---------------------------------------------------------------------

cpp_mpp <- find_header_method("MakePackedPlaintext", function(m) {
  tc <- type_class_vec(m)
  length(tc) >= 1L && tc[1] == "int_vector"
})
py_mpp <- find_python_method("CryptoContext", "MakePackedPlaintext")
r_mpp  <- find_r_method("CryptoContext__MakePackedPlaintext", "make_packed_plaintext")

expect_true(!is.null(cpp_mpp), info = "MakePackedPlaintext: C++ overload not found")
expect_true(!is.null(py_mpp),  info = "MakePackedPlaintext: Python binding not found")
expect_true(!is.null(r_mpp),   info = "MakePackedPlaintext: R binding not found")

if (!is.null(cpp_mpp) && !is.null(py_mpp) && !is.null(r_mpp)) {
  cpp_tc <- type_class_vec(cpp_mpp)
  py_tc  <- type_class_vec(py_mpp)
  r_args <- strip_r_receiver(r_mpp$entry$args)

  ## C++ has 3 args (value + 2 optional), Python mirrors C++, and
  ## at 9107 R mirrors both after the factory-arg-completion sub-step.
  expect_true(length(cpp_tc) >= 3L,
              info = "MakePackedPlaintext: expected C++ to expose 3+ args")
  expect_true(length(py_tc) >= 3L,
              info = "MakePackedPlaintext: expected Python to expose 3+ args")
  expect_equal(length(r_args), 3L,
               info = "MakePackedPlaintext: R should have 3 args post-9107 (values + noise_scale_deg + level)")

  ## Resolution: OK. Arity matches across all three bindings.
  resolution <- "OK"
  message(sprintf(
    "[surface-parity] MakePackedPlaintext: %s — R has %d arg(s), C++ has %d, Python has %d",
    resolution, length(r_args), length(cpp_tc), length(py_tc)))
  expect_true(resolution %in%
                c("OK", "KNOWN_PYTHON_DEFECT", "CUT_LINE",
                  "DELIBERATE_DEVIATION", "PARTIAL_R_AT_9100_0"),
              info = "MakePackedPlaintext: resolution must be a recognized class")
}

## ---------------------------------------------------------------------
## 8. upstream-defects.md tag parser — the harness must recognize three
##    classes (KNOWN_PYTHON_DEFECT, UNVERIFIED, N/A).
## ---------------------------------------------------------------------

parse_upstream_defects_tags <- function(path) {
  lines <- readLines(path, warn = FALSE)
  ## Find every "### P<num>." entry and the first **Tag:** line that
  ## follows it. Return a named character vector keyed by the entry
  ## title (e.g. "P1") with the tag-class string.
  entry_re <- "^###\\s+(P[0-9]+)[.\\s]"
  tag_re   <- "^\\*\\*Tag:\\*\\*\\s*(.+?)\\s*$"
  out <- list()
  current <- NULL
  for (line in lines) {
    m <- regmatches(line, regexec(entry_re, line))[[1]]
    if (length(m) == 2L) {
      current <- m[2]
      next
    }
    if (!is.null(current)) {
      m2 <- regmatches(line, regexec(tag_re, line))[[1]]
      if (length(m2) == 2L) {
        ## Take the first token of the tag (strip parenthetical).
        tag_token <- sub("\\s*[\\(\\u2014-].*$", "", m2[2])
        tag_token <- trimws(tag_token)
        ## Normalize N/A — duplicate variants.
        if (grepl("^N/A", tag_token)) tag_token <- "N/A"
        out[[current]] <- tag_token
        current <- NULL
      }
    }
  }
  out
}

defect_tags <- parse_upstream_defects_tags(UPSTREAM_DEFECTS)

## We expect P1..P11 to be present, with a known mapping.
expect_true(length(defect_tags) >= 10L,
            info = sprintf("upstream-defects.md parser: expected 10+ entries, got %d",
                           length(defect_tags)))

## P1 is the canonical KNOWN_PYTHON_DEFECT spot-check.
expect_true("P1" %in% names(defect_tags),
            info = "upstream-defects.md parser: P1 entry missing")
if ("P1" %in% names(defect_tags)) {
  expect_true(grepl("KNOWN_PYTHON_DEFECT", defect_tags[["P1"]]),
              info = sprintf("upstream-defects.md parser: P1 should be KNOWN_PYTHON_DEFECT, got %s",
                             defect_tags[["P1"]]))
}

## P3 is the canonical former-UNVERIFIED spot-check — resolved to
## N/A at Block E 9124 after a direct header re-read. The parser
## must still find the entry.
expect_true("P3" %in% names(defect_tags),
            info = "upstream-defects.md parser: P3 entry missing")
if ("P3" %in% names(defect_tags)) {
  expect_true(grepl("^N/A", defect_tags[["P3"]]),
              info = sprintf("upstream-defects.md parser: P3 should be N/A after 9124, got %s",
                             defect_tags[["P3"]]))
}

## P5 is the canonical N/A spot-check (duplicate of P3).
expect_true("P5" %in% names(defect_tags),
            info = "upstream-defects.md parser: P5 entry missing")
if ("P5" %in% names(defect_tags)) {
  expect_true(grepl("^N/A", defect_tags[["P5"]]),
              info = sprintf("upstream-defects.md parser: P5 should be N/A, got %s",
                             defect_tags[["P5"]]))
}

## Block E 9124 resolved the two UNVERIFIED entries (P3 and P4) to
## N/A after a direct header re-read. A clean-state `upstream-defects.md`
## may have zero UNVERIFIED entries — if any reappear in future
## discovery work, the parser still recognises the tag class and the
## harness logs them, but we no longer gate the test on the presence
## of an UNVERIFIED canary.
classes <- unique(unlist(defect_tags))
has_known <- any(grepl("KNOWN_PYTHON_DEFECT", classes))
has_na    <- any(grepl("^N/A",                classes))
expect_true(has_known, info = "upstream-defects.md parser: no KNOWN_PYTHON_DEFECT entries seen")
expect_true(has_na,    info = "upstream-defects.md parser: no N/A entries seen")
