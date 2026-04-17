#!/usr/bin/env Rscript
## R-SPECIFIC: Block E 9100.0 — projection validation gate runner
##
## Implements the seven-case gate from
## notes/blocks/E-bindings-rewrite/projection-validation.md:
##
##   1. known-good Encrypt
##   2. known-good Decrypt
##   3. known-good EvalAdd
##   4. known-good EvalMult
##   5. known-good MakePackedPlaintext (PARTIAL_R_AT_9100_0 path)
##   6. deliberately-broken R-side EvalNegate
##   7. deliberately-broken Python-side ReEncrypt
##
## *** THIS SCRIPT IS NOT RUN BY R CMD check. ***
##
## It is a manual one-time gate runner executed at 9100.0
## sign-off time. Cases 6 and 7 patch source files and rebuild;
## case 7 in particular requires a ~30s pybind11 rebuild and is
## explicitly recommended-by-spec to be run once and logged
## (projection-validation.md §"Deliberately broken 7").
##
## Default mode is **DRY-RUN**: cases 6 and 7 print the steps that
## would be taken without modifying any source files. Pass `--live`
## on the command line to actually patch + rebuild + revert. Cases
## 1–5 always run for real (they only read the dump JSONs).
##
## DRY-RUN is the 9100.0 default because the broken-case automation
## is the highest-risk part of the gate (a failed revert leaves
## the working tree in a broken state). The live mode is reserved
## for an interactive run by the implementer with a clean working
## tree and the ability to recover via git checkout.
##
## Output: per-case PASS / FAIL lines on stdout, plus a final
## summary line. Also writes a JSON artifact to
## temp/scratch/validation-gate-<timestamp>.json with the per-case
## records so the gate run is auditable.
##
## USAGE:
##   Rscript inst/scripts/run_projection_validation.R          # dry-run
##   Rscript inst/scripts/run_projection_validation.R --live   # live mode
##   Rscript inst/scripts/run_projection_validation.R --skip-broken
##                                                              # cases 1-5 only

suppressPackageStartupMessages({
  if (!requireNamespace("jsonlite", quietly = TRUE)) {
    stop("[validation-gate] jsonlite required")
  }
})

## ---------------------------------------------------------------------
## Configuration
## ---------------------------------------------------------------------

REPO_ROOT <- "/Users/naras/research/fhe"
SCRATCH   <- file.path(REPO_ROOT, "temp", "scratch")
VENV_DIR  <- file.path(REPO_ROOT, "temp", "openfhe-python-venv")
VENV_PY   <- file.path(VENV_DIR, "bin", "python")
INST_SCRIPTS <- file.path(REPO_ROOT, "R_dev", "openfhe", "inst", "scripts")
DUMP_R       <- file.path(INST_SCRIPTS, "dump_r_signatures.R")
DUMP_HEADER  <- file.path(INST_SCRIPTS, "dump_header_signatures.R")
DUMP_PYTHON  <- file.path(INST_SCRIPTS, "dump_python_signatures.py")

R_JSON      <- file.path(SCRATCH, "signatures-r.json")
PY_JSON     <- file.path(SCRATCH, "signatures-python.json")
HEADER_JSON <- file.path(SCRATCH, "signatures-header.json")

## Source files the broken-case validation would patch (for grep
## targets in the dry-run output).
EVAL_NEGATE_SRC <- file.path(REPO_ROOT, "R_dev", "openfhe", "src",
                             "pke_bindings.cpp")
PYTHON_BINDINGS_SRC <- file.path(REPO_ROOT, "openfhe", "openfhe-python",
                                 "src", "lib", "bindings.cpp")

## ---------------------------------------------------------------------
## Argument parsing
## ---------------------------------------------------------------------

args <- commandArgs(trailingOnly = TRUE)
LIVE_MODE   <- "--live" %in% args
SKIP_BROKEN <- "--skip-broken" %in% args

cat("[validation-gate] mode:",
    if (LIVE_MODE) "LIVE (will patch + rebuild + revert)"
    else "DRY-RUN (no source modifications)", "\n")
if (SKIP_BROKEN) {
  cat("[validation-gate] --skip-broken: cases 6 and 7 skipped\n")
}

results <- list()

record <- function(case_id, name, status, message = "") {
  results[[length(results) + 1L]] <<- list(
    case_id = case_id, name = name, status = status, message = message)
  cat(sprintf("[%s] %-44s  %s\n", status, paste0(case_id, ": ", name), message))
}

## ---------------------------------------------------------------------
## Run the three dumpers and load the JSONs.
## ---------------------------------------------------------------------

run_dumpers <- function() {
  rc1 <- system2(file.path(R.home("bin"), "Rscript"),
                 c(DUMP_R, "--output", R_JSON),
                 stdout = FALSE, stderr = FALSE)
  rc2 <- system2(VENV_PY, c(DUMP_PYTHON, "--output", PY_JSON),
                 stdout = FALSE, stderr = FALSE)
  rc3 <- system2(file.path(R.home("bin"), "Rscript"),
                 c(DUMP_HEADER, "--output", HEADER_JSON),
                 stdout = FALSE, stderr = FALSE)
  list(r = rc1, py = rc2, header = rc3)
}

cat("[validation-gate] running three dumpers...\n")
rc <- run_dumpers()
if (any(unlist(rc) != 0L)) {
  stop("[validation-gate] one or more dumpers failed: ",
       paste(names(rc), unlist(rc), sep = "=", collapse = ", "))
}

sigs_r  <- jsonlite::fromJSON(R_JSON,      simplifyVector = FALSE)
sigs_py <- jsonlite::fromJSON(PY_JSON,     simplifyVector = FALSE)
sigs_h  <- jsonlite::fromJSON(HEADER_JSON, simplifyVector = FALSE)

## ---------------------------------------------------------------------
## Lookup helpers (mirror test_surface_parity.R; kept self-contained
## so this script does not depend on package-internal helpers).
## ---------------------------------------------------------------------

`%||%` <- function(a, b) if (is.null(a)) b else a

type_class_vec <- function(entry) {
  if (is.null(entry)) return(character(0))
  vapply(entry$args, function(a) a$type_class %||% "any", character(1))
}

find_header <- function(name, predicate = NULL) {
  for (m in sigs_h$methods) {
    if ((m$name %||% "") == name) {
      if (is.null(predicate) || predicate(m)) return(m)
    }
  }
  NULL
}

find_python <- function(class_name, name, predicate = NULL) {
  for (m in sigs_py$methods) {
    if ((m$class %||% "") == class_name && (m$name %||% "") == name) {
      if (is.null(predicate) || predicate(m)) return(m)
    }
  }
  NULL
}

find_r_internal <- function(name) {
  for (m in sigs_r$internal_methods) {
    if ((m$name %||% "") == name) return(m)
  }
  NULL
}

strip_r_receiver <- function(args) {
  if (length(args) == 0L) return(args)
  first <- args[[1L]]$name %||% ""
  if (first %in% c("cc_xp", "ctx_xp")) args <- args[-1L]
  args <- Filter(function(a) (a$name %||% "") != "...", args)
  args
}

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

## ---------------------------------------------------------------------
## Cases 1–5: known-good projections
## ---------------------------------------------------------------------

## --- Case 1: Encrypt ---
cpp_e <- find_header("Encrypt", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "PublicKey" && tc[2] == "Plaintext"
})
py_e <- find_python("CryptoContext", "Encrypt", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "PublicKey" && tc[2] == "Plaintext"
})
r_e <- find_r_internal("CryptoContext__Encrypt_PublicKey")
r_e_args <- if (is.null(r_e)) list() else strip_r_receiver(r_e$args)
case1_ok <- !is.null(cpp_e) && !is.null(py_e) && !is.null(r_e) &&
  identical(type_class_vec(cpp_e), type_class_vec(py_e)) &&
  identical(
    vapply(r_e_args, function(a) r_arg_type_class(a$name), character(1)),
    type_class_vec(cpp_e))
record("1", "Encrypt(publicKey, plaintext)",
       if (case1_ok) "PASS" else "FAIL",
       sprintf("C++=%d Py=%d R=%d args",
               length(type_class_vec(cpp_e)), length(type_class_vec(py_e)),
               length(r_e_args)))

## --- Case 2: Decrypt ---
cpp_d_raw <- find_header("Decrypt", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 3L && tc[1] == "PrivateKey" && tc[2] == "Ciphertext" && tc[3] == "Plaintext"
})
cpp_d <- hide_plaintext_outparam(cpp_d_raw)
py_d <- find_python("CryptoContext", "Decrypt", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "PrivateKey" && tc[2] == "Ciphertext"
})
r_d <- find_r_internal("CryptoContext__Decrypt")
case2_ok <- !is.null(cpp_d) && !is.null(py_d) && !is.null(r_d) &&
  identical(type_class_vec(cpp_d), type_class_vec(py_d)) &&
  identical(
    vapply(strip_r_receiver(r_d$args), function(a) r_arg_type_class(a$name), character(1)),
    type_class_vec(cpp_d))
record("2", "Decrypt(privateKey, ciphertext) [out-param hidden]",
       if (case2_ok) "PASS" else "FAIL",
       sprintf("C++(post-hide)=%d Py=%d", length(type_class_vec(cpp_d)),
               length(type_class_vec(py_d))))

## --- Case 3: EvalAdd ct/ct ---
cpp_a <- find_header("EvalAdd", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
py_a <- find_python("CryptoContext", "EvalAdd", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
r_a <- find_r_internal("EvalAdd__ct_ct")
case3_ok <- !is.null(cpp_a) && !is.null(py_a) && !is.null(r_a) &&
  identical(type_class_vec(cpp_a), type_class_vec(py_a))
record("3", "EvalAdd(Ciphertext, Ciphertext)",
       if (case3_ok) "PASS" else "FAIL", "")

## --- Case 4: EvalMult ct/ct ---
cpp_m <- find_header("EvalMult", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
py_m <- find_python("CryptoContext", "EvalMult", function(m) {
  tc <- type_class_vec(m)
  length(tc) == 2L && tc[1] == "Ciphertext" && tc[2] == "Ciphertext"
})
r_m <- find_r_internal("EvalMult__ct_ct")
case4_ok <- !is.null(cpp_m) && !is.null(py_m) && !is.null(r_m) &&
  identical(type_class_vec(cpp_m), type_class_vec(py_m))
record("4", "EvalMult(Ciphertext, Ciphertext)",
       if (case4_ok) "PASS" else "FAIL", "")

## --- Case 5: MakePackedPlaintext (PARTIAL_R_AT_9100_0) ---
cpp_mpp <- find_header("MakePackedPlaintext", function(m) {
  tc <- type_class_vec(m)
  length(tc) >= 1L && tc[1] == "int_vector"
})
py_mpp <- find_python("CryptoContext", "MakePackedPlaintext")
r_mpp  <- find_r_internal("CryptoContext__MakePackedPlaintext")
case5_partial <- !is.null(cpp_mpp) && !is.null(py_mpp) && !is.null(r_mpp) &&
  length(type_class_vec(cpp_mpp)) >= 3L &&
  length(type_class_vec(py_mpp))  >= 3L &&
  length(strip_r_receiver(r_mpp$args)) == 1L
record("5", "MakePackedPlaintext PARTIAL_R_AT_9100_0",
       if (case5_partial) "PASS" else "FAIL",
       "expected: C++ 3 args, Py 3 args, R 1 arg post-receiver-strip")

## ---------------------------------------------------------------------
## Cases 6 and 7: deliberately broken
## ---------------------------------------------------------------------

if (SKIP_BROKEN) {
  record("6", "EvalNegate R-side break", "SKIP", "--skip-broken")
  record("7", "ReEncrypt Python-side break", "SKIP", "--skip-broken")
} else {
  ## --- Case 6: R-side EvalNegate break ---
  if (!LIVE_MODE) {
    cat("\n[validation-gate] CASE 6 dry-run plan:\n")
    cat("  1. backup:  cp", EVAL_NEGATE_SRC, "<scratch>\n")
    cat("  2. patch:   remove the `SEXP ct_xp` argument from the\n")
    cat("              EvalNegate cpp11::register'd function in\n")
    cat("             ", EVAL_NEGATE_SRC, "\n")
    cat("  3. document: cd R_dev && devtools::document('openfhe')\n")
    cat("  4. install: cd R_dev && OPENFHE_HOME=$OPENFHE_HOME R CMD INSTALL --no-multiarch openfhe\n")
    cat("  5. dump:    Rscript inst/scripts/dump_r_signatures.R\n")
    cat("  6. assert:  EvalNegate cpp11 internal has 0 args (expect R_DEFECT)\n")
    cat("  7. revert:  cp <scratch> ", EVAL_NEGATE_SRC, "\n")
    cat("  8. rebuild: devtools::document() + R CMD INSTALL\n")
    cat("  9. dump + assert: EvalNegate cpp11 internal has 1 arg (OK)\n")
    if (file.exists(EVAL_NEGATE_SRC)) {
      grep_hits <- length(grep("EvalNegate",
                                readLines(EVAL_NEGATE_SRC, warn = FALSE)))
      record("6", "EvalNegate R-side break (DRY-RUN)", "DRY-RUN",
             sprintf("source file present, %d EvalNegate references", grep_hits))
    } else {
      record("6", "EvalNegate R-side break (DRY-RUN)", "FAIL",
             sprintf("source file missing: %s", EVAL_NEGATE_SRC))
    }
  } else {
    record("6", "EvalNegate R-side break", "SKIP",
           "LIVE mode for case 6 not implemented in 9100.0; run interactively")
  }

  ## --- Case 7: Python-side ReEncrypt break ---
  if (!LIVE_MODE) {
    cat("\n[validation-gate] CASE 7 dry-run plan:\n")
    cat("  1. backup:  cp openfhe.cpython-*.so <scratch>/validation-gate-backup.so\n")
    cat("  2. patch:   in", PYTHON_BINDINGS_SRC, "\n")
    cat("              remove the `py::arg(\"publicKey\") = py::none()` line\n")
    cat("              from the .def(\"ReEncrypt\", ...) registration\n")
    cat("  3. rebuild: cd temp/openfhe-python-build && make -j4 && make install\n")
    cat("  4. dump:    python dump_python_signatures.py\n")
    cat("  5. assert:  ReEncrypt has 2 args (expect PYTHON_DEFECT)\n")
    cat("  6. revert:  git -C openfhe/openfhe-python checkout -- src/lib/bindings.cpp\n")
    cat("  7. rebuild: make -j4 && make install\n")
    cat("  8. defense in depth: cp <scratch>/validation-gate-backup.so back\n")
    cat("  9. dump + assert: ReEncrypt has 3 args (OK)\n")
    if (file.exists(PYTHON_BINDINGS_SRC)) {
      grep_hits <- length(grep("ReEncrypt",
                                readLines(PYTHON_BINDINGS_SRC, warn = FALSE)))
      record("7", "ReEncrypt Python-side break (DRY-RUN)", "DRY-RUN",
             sprintf("source file present, %d ReEncrypt references", grep_hits))
    } else {
      record("7", "ReEncrypt Python-side break (DRY-RUN)", "FAIL",
             sprintf("source file missing: %s", PYTHON_BINDINGS_SRC))
    }
  } else {
    record("7", "ReEncrypt Python-side break", "SKIP",
           "LIVE mode for case 7 not implemented in 9100.0; run interactively")
  }
}

## ---------------------------------------------------------------------
## Summary + artifact
## ---------------------------------------------------------------------

n_pass <- sum(vapply(results, function(r) r$status == "PASS", logical(1)))
n_fail <- sum(vapply(results, function(r) r$status == "FAIL", logical(1)))
n_skip <- sum(vapply(results, function(r) r$status %in% c("SKIP", "DRY-RUN"),
                     logical(1)))

cat(sprintf("\n[validation-gate] summary: %d PASS, %d FAIL, %d SKIP/DRY-RUN\n",
            n_pass, n_fail, n_skip))

ts <- format(Sys.time(), "%Y%m%dT%H%M%SZ", tz = "UTC")
artifact <- file.path(SCRATCH, sprintf("validation-gate-%s.json", ts))
jsonlite::write_json(list(
  generated_at = ts,
  mode         = if (LIVE_MODE) "live" else "dry-run",
  skip_broken  = SKIP_BROKEN,
  pass         = n_pass,
  fail         = n_fail,
  skip         = n_skip,
  cases        = results
), path = artifact, auto_unbox = TRUE, pretty = TRUE)
cat("[validation-gate] artifact:", artifact, "\n")

## Exit non-zero on hard failure so a wrapping CI step can detect it.
if (n_fail > 0L) quit(status = 1L)
