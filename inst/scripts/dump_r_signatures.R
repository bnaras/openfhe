#!/usr/bin/env Rscript
## R-SPECIFIC: dump every exported R symbol's signature for the
## Block E parity harness (Signal 1, R-side dumper).
##
## Reads the installed `openfhe` package's NAMESPACE export list,
## walks `formals()` for every exported symbol, and writes a JSON
## file with the projection schema documented in
## `notes/blocks/E-bindings-rewrite/harness.md` §2.1.
##
## The output JSON is consumed by
## `temp/openfhe-python-venv/normalize_projection.py` which aligns
## the R / Python / C++ projections into the three-way diff input
## that `inst/tinytest/test_surface_parity.R` reads.
##
## USAGE:
##   Rscript inst/scripts/dump_r_signatures.R \
##     --output /Users/naras/research/fhe/temp/scratch/signatures-r.json
##
##   The script must be run with the `openfhe` package installed.
##   It does NOT load the package via `devtools::load_all()` — it
##   uses `library(openfhe)` so that NAMESPACE export semantics are
##   preserved exactly as a user would see them.

suppressPackageStartupMessages({
  library(jsonlite)
})

main <- function(args) {
  output <- parse_output_arg(args)
  message("[dump_r_signatures] writing ", output)

  ## Load openfhe via library() so NAMESPACE semantics apply.
  if (!requireNamespace("openfhe", quietly = TRUE)) {
    stop("[dump_r_signatures] the openfhe package is not installed.\n",
         "  Build it first: cd R_dev && R CMD INSTALL --no-multiarch openfhe")
  }
  suppressPackageStartupMessages(library(openfhe))

  ## Walk every exported symbol from the openfhe NAMESPACE.
  exported <- getNamespaceExports("openfhe")
  exported <- sort(exported)

  methods_payload <- lapply(exported, function(name) {
    obj <- tryCatch(get(name, envir = asNamespace("openfhe")),
                    error = function(e) NULL)
    if (is.null(obj)) {
      return(list(name = name, kind = "missing", error = "could not resolve symbol"))
    }
    project_object(name, obj)
  })

  ## Walk every cpp11-internal symbol so the harness can also cross
  ## reference internal binding signatures against the C++ side. These
  ## live in the openfhe namespace but are NOT exported; reading them
  ## from `cpp11.R` is the canonical source.
  cpp11_path <- system.file("R", "cpp11.R", package = "openfhe")
  if (cpp11_path == "" || !file.exists(cpp11_path)) {
    cpp11_path <- find_cpp11_R()
  }
  internal_payload <- if (file.exists(cpp11_path)) {
    project_cpp11_internals(cpp11_path)
  } else {
    list()
  }

  payload <- list(
    schema_version       = "1",
    source               = "r",
    package_version      = as.character(utils::packageVersion("openfhe")),
    generated_at         = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
    exported_count       = length(methods_payload),
    internal_count       = length(internal_payload),
    methods              = methods_payload,
    internal_methods     = internal_payload
  )

  ## Ensure parent dir exists.
  dir.create(dirname(output), recursive = TRUE, showWarnings = FALSE)
  writeLines(jsonlite::toJSON(payload, auto_unbox = TRUE, null = "null",
                              pretty = TRUE),
             con = output)
  message("[dump_r_signatures] wrote ", length(methods_payload),
          " exported + ", length(internal_payload), " internal entries")
}

## Project a single R object (function, S7 generic, S7 class, list of
## constants representing an enum, etc.) into the harness JSON schema.
project_object <- function(name, obj) {
  if (is.function(obj)) {
    return(project_function(name, obj))
  }
  if (inherits(obj, "S7_class")) {
    return(project_s7_class(name, obj))
  }
  if (inherits(obj, "S7_generic")) {
    return(project_s7_generic(name, obj))
  }
  if (is.list(obj) && all(vapply(obj, is.numeric, logical(1)))) {
    ## Enum-style list of named integers.
    return(list(
      name = name,
      kind = "enum",
      values = lapply(names(obj), function(v) {
        list(name = v, value = as.integer(obj[[v]]))
      })
    ))
  }
  list(name = name, kind = "other", class = class(obj)[1])
}

project_function <- function(name, fn) {
  fmls <- formals(fn)
  arg_names <- names(fmls)
  ## as.character() on the whole pairlist returns an empty string for
  ## arguments with no default (the only way to detect missing-arg
  ## without triggering the empty-symbol evaluation error). For
  ## non-missing arguments it returns the deparse of the default
  ## expression, which we re-parse below if we need the value.
  defaults_str <- as.character(fmls)
  list(
    name        = name,
    kind        = "function",
    return_type = "any",  # type system not encoded in R signatures
    args        = lapply(seq_along(arg_names), function(i) {
      project_default(arg_names[i], defaults_str[i], fmls[i])
    })
  )
}

project_s7_generic <- function(name, generic) {
  ## Walk the generic's methods to surface dispatch targets.
  methods <- tryCatch(S7::methods(generic), error = function(e) list())
  list(
    name    = name,
    kind    = "s7_generic",
    methods = lapply(seq_along(methods), function(i) {
      m <- methods[[i]]
      list(
        signature = format(attr(m, "class_signature") %||% "any"),
        formals   = lapply(seq_along(formals(m)), function(j) {
          project_default(names(formals(m))[j], formals(m)[[j]])
        })
      )
    })
  )
}

project_s7_class <- function(name, cls) {
  list(
    name       = name,
    kind       = "s7_class",
    properties = if (is.null(cls@properties)) list() else names(cls@properties)
  )
}

## Render a single formal argument to the schema. `default_str` is
## the as.character() form of the i-th formals slice ("" for no
## default); `default_slice` is the 1-element pairlist used to recover
## the value when not missing.
project_default <- function(arg_name, default_str, default_slice) {
  ## Empty formal → no default at all.
  if (default_str == "") {
    return(list(name = arg_name, default_class = "none"))
  }
  ## NULL default.
  if (default_str == "NULL") {
    return(list(name = arg_name, default_class = "null", default_value = NULL))
  }
  ## At this point we know the default is not missing; we can safely
  ## pull the value out of the slice via `[[1]]`.
  default_obj <- default_slice[[1]]
  ## Literal scalar defaults.
  if (is.numeric(default_obj) && length(default_obj) == 1L) {
    cls <- if (is.integer(default_obj)) "int_literal" else "double_literal"
    return(list(name = arg_name, default_class = cls,
                default_value = unname(default_obj)))
  }
  if (is.logical(default_obj) && length(default_obj) == 1L) {
    return(list(name = arg_name, default_class = "bool_literal",
                default_value = unname(default_obj)))
  }
  if (is.character(default_obj) && length(default_obj) == 1L) {
    return(list(name = arg_name, default_class = "string_literal",
                default_value = unname(default_obj)))
  }
  ## Anything else (a call, a symbol, a vector default) is a
  ## non-constant default and gets recorded as such for manual review.
  list(name = arg_name, default_class = "non_constant",
       default_value = default_str)
}

## Walk the auto-generated cpp11.R wrapper file to extract every
## cpp11::register'ed function name and its formals. This is read
## from the file rather than from the package namespace because the
## cpp11 wrappers are not exported and getNamespace() would give us
## just the function objects (whose formals are correct but whose
## names we already know from this walk).
project_cpp11_internals <- function(cpp11_path) {
  ## Source cpp11.R into a fresh environment so we can walk its
  ## function objects without polluting the global namespace.
  env <- new.env(parent = baseenv())
  ## cpp11.R relies on the parent namespace having `.Call` available;
  ## inject it.
  env$.Call <- function(...) NULL
  tryCatch(
    sys.source(cpp11_path, envir = env, keep.source = FALSE),
    error = function(e) {
      message("[dump_r_signatures] cpp11.R source warning: ", conditionMessage(e))
    }
  )
  syms <- ls(envir = env)
  syms <- setdiff(syms, ".Call")
  lapply(sort(syms), function(name) {
    obj <- env[[name]]
    if (!is.function(obj)) return(NULL)
    project_function(name, obj)
  }) |>
    Filter(Negate(is.null), x = _)
}

`%||%` <- function(a, b) if (is.null(a)) b else a

find_cpp11_R <- function() {
  ## Fall back: if system.file failed, try the installed library path.
  paths <- c(
    file.path(.libPaths(), "openfhe", "R", "cpp11.R"),
    "/Users/naras/research/fhe/R_dev/openfhe/R/cpp11.R"
  )
  paths <- paths[file.exists(paths)]
  if (length(paths)) paths[1] else ""
}

parse_output_arg <- function(args) {
  if (length(args) == 0L) {
    return("/Users/naras/research/fhe/temp/scratch/signatures-r.json")
  }
  for (i in seq_along(args)) {
    if (args[i] == "--output" && i < length(args)) return(args[i + 1L])
    if (startsWith(args[i], "--output=")) {
      return(sub("^--output=", "", args[i]))
    }
  }
  "/Users/naras/research/fhe/temp/scratch/signatures-r.json"
}

if (sys.nframe() == 0L) {
  main(commandArgs(trailingOnly = TRUE))
}
