#!/usr/bin/env Rscript
## R-SPECIFIC: dump every public method declaration from the OpenFHE
## C++ headers for the Block E parity harness (Signal 1, header source).
##
## This is the regex-based fallback parser for the C++ header source
## of harness.md §2.2 / Signal 1. The harness spec lists libclang as
## the preferred parser. libclang 18 was attempted in the reference
## venv but bailed on macOS 25 / Xcode 21 system headers (the
## `<bit>` include references `__builtin_ctzg` / `__builtin_clzg`
## which libclang 18's bundled clang frontend does not implement).
## Per the spec carve-out ("If libclang is taking more than 30
## minutes to make work, fall back to the regex parser and document
## the libclang attempt"), we ship the regex walker.
##
## Originally implemented in Python at
## `temp/openfhe-python-venv/dump_signatures.py --source=header`
## (since libclang lives in the Python ecosystem). Migrated to R
## at 9100.0 because the regex parser does not need a Python
## environment — it walks plain text — and keeping it in R puts
## both the C++ header dumper and the R formals dumper alongside
## each other under `inst/scripts/`. The Python sibling
## `dump_python_signatures.py` retains only the inspect.getdoc
## walk that genuinely requires a `import openfhe`.
##
## When libclang becomes usable (post-Xcode upgrade or a newer
## libclang wheel), this file is replaced by an `inst/scripts/dump_header_signatures.py`
## that drives libclang directly. The two implementations must
## emit the same JSON schema (see harness.md §2.1).
##
## USAGE:
##   Rscript inst/scripts/dump_header_signatures.R \
##     --output=/Users/naras/research/fhe/temp/scratch/signatures-header.json
##
## OPENFHE PYTHON SOURCE (historical):
##   temp/openfhe-python-venv/dump_signatures.py --source=header (deleted at 9100.0)

suppressPackageStartupMessages({
  library(jsonlite)
})

SCHEMA_VERSION <- "1"

DEFAULT_OUTPUT <- "/Users/naras/research/fhe/temp/scratch/signatures-header.json"

OPENFHE_INCLUDE <- "/Users/naras/research/fhe/temp/openfhe-rlibomp/include/openfhe"
HEADERS <- c(
  file.path(OPENFHE_INCLUDE, "pke", "cryptocontext.h"),
  file.path(OPENFHE_INCLUDE, "binfhe", "binfhecontext.h")
)

S7_CLASS_NAMES <- c(
  "CryptoContext", "BFVParams", "BGVParams", "CKKSParams",
  "CCParamsBFVRNS", "CCParamsBGVRNS", "CCParamsCKKSRNS",
  "PublicKey", "PrivateKey", "KeyPair", "Plaintext", "Ciphertext",
  "FastRotationPrecomputation", "EvalKey", "EvalKeyMap",
  "LWECiphertext", "LWEPrivateKey", "BinFHEContext",
  "CryptoParameters", "EncodingParams", "ElementParams"
)

ENUM_NAMES <- c(
  "PKESchemeFeature", "ScalingTechnique", "CKKSDataType", "SecurityLevel",
  "ScalingModSize", "ProxyReEncryptionMode", "DecryptionNoiseMode",
  "EncryptionTechnique", "SCHEME", "BINFHE_PARAMSET", "BINGATE",
  "BINFHE_METHOD", "BINFHE_OUTPUT", "MultipartyMode", "ExecutionMode",
  "COMPRESSION_LEVEL", "CompressionLevel", "KeySwitchTechnique",
  "MultiplicationTechnique", "PlaintextEncodings"
)

INT_C_TYPES <- c(
  "size_t", "uint32_t", "uint64_t", "int32_t", "int64_t", "int",
  "usint", "PlaintextModulus", "NativeInteger", "long", "unsigned",
  "unsigned int", "unsigned long"
)
INT_VECTOR_INNER <- c(
  "int64_t", "int32_t", "uint64_t", "uint32_t", "int", "size_t",
  "usint", "PlaintextModulus"
)

main <- function(args) {
  output <- parse_output_arg(args)
  message("[dump_header_signatures] writing ", output)

  methods <- list()
  for (h in HEADERS) {
    if (!file.exists(h)) {
      message("[dump_header_signatures] header missing: ", h)
      next
    }
    methods <- c(methods, parse_header_methods(h))
  }

  payload <- list(
    schema_version  = SCHEMA_VERSION,
    source          = "header",
    package_version = "openfhe-1.5.1 (regex parser fallback)",
    generated_at    = format(Sys.time(), "%Y-%m-%dT%H:%M:%SZ", tz = "UTC"),
    exported_count  = length(methods),
    methods         = methods
  )

  dir.create(dirname(output), recursive = TRUE, showWarnings = FALSE)
  writeLines(jsonlite::toJSON(payload, auto_unbox = TRUE, null = "null",
                              pretty = TRUE),
             con = output)
  message("[dump_header_signatures] wrote ", length(methods), " methods")
}

## Strip /* ... */ block comments and // line comments.
strip_comments <- function(text) {
  ## Block comments: use a non-greedy match across newlines. The
  ## (?s) inline flag makes `.` match newlines (PCRE's default is
  ## not to, unlike Python's `re.DOTALL`).
  text <- gsub("(?s)/\\*.*?\\*/", " ", text, perl = TRUE)
  ## Line comments
  text <- gsub("//[^\n]*", "", text, perl = TRUE)
  text
}

## Walk the header source character-by-character and emit one chunk
## per top-level declaration (between `;` and `{` separators at
## paren-depth 0). Recurses into class/struct/namespace bodies; skips
## past function bodies. This mirrors the Python `_join_decls`
## function in the original `dump_signatures.py` line for line.
join_decls <- function(text) {
  ## Drop preprocessor lines first.
  lines <- strsplit(text, "\n", fixed = TRUE)[[1]]
  lines <- lines[!grepl("^\\s*#", lines)]
  joined <- paste(lines, collapse = "\n")

  ## We walk the joined string character by character. R is slow at
  ## per-character indexing on long strings; convert once to a
  ## raw-int vector and index that.
  chars <- strsplit(joined, "", fixed = TRUE)[[1]]
  n <- length(chars)

  out <- character()
  i <- 1L
  chunk_start <- 1L
  paren <- 0L

  emit <- function(start, end_inclusive) {
    chunk <- paste(chars[start:end_inclusive], collapse = "")
    chunk_norm <- gsub("\\s+", " ", chunk, perl = TRUE)
    chunk_norm <- trimws(chunk_norm)
    if (nzchar(chunk_norm)) out[[length(out) + 1L]] <<- chunk_norm
  }

  while (i <= n) {
    ch <- chars[i]
    if (ch == "(") {
      paren <- paren + 1L
      i <- i + 1L
      next
    }
    if (ch == ")") {
      paren <- paren - 1L
      i <- i + 1L
      next
    }
    if (paren > 0L) {
      i <- i + 1L
      next
    }
    if (ch == ";") {
      emit(chunk_start, i)
      chunk_start <- i + 1L
      i <- i + 1L
      next
    }
    if (ch == "{") {
      emit(chunk_start, i)
      ## Was the chunk just emitted a container opener
      ## (class/struct/namespace/...)?
      last_chunk <- if (length(out) > 0L) out[[length(out)]] else ""
      if (is_container_open(last_chunk)) {
        ## Recurse: continue past the '{' and let the walker see the
        ## inner declarations as separate chunks.
        chunk_start <- i + 1L
        i <- i + 1L
        next
      } else {
        ## Function body — skip to matching '}'.
        depth <- 1L
        i <- i + 1L
        while (i <= n && depth > 0L) {
          c2 <- chars[i]
          if (c2 == "{") depth <- depth + 1L
          else if (c2 == "}") depth <- depth - 1L
          i <- i + 1L
        }
        chunk_start <- i
        next
      }
    }
    if (ch == "}") {
      ## End of a container body; treat as a separator and reset.
      chunk_start <- i + 1L
      i <- i + 1L
      next
    }
    i <- i + 1L
  }
  out
}

## True if `chunk` (ending in '{') opens a class/struct/namespace
## body that should be recursed into.
is_container_open <- function(chunk) {
  s <- trimws(chunk)
  if (!grepl("\\{$", s)) return(FALSE)
  grepl(
    "^(?:template\\s*<[^>]*>\\s*)?(?:export\\s+)?(?:class|struct|namespace|union|enum|extern)\\b",
    s, perl = TRUE
  )
}

## Method declaration regex — captures return type, method name, arg
## list, trailing modifiers. Same as the Python `_METHOD_RE`.
METHOD_RE <- paste0(
  "^\\s*",
  "(?:virtual\\s+)?",
  "(?:static\\s+)?",
  "(?:inline\\s+)?",
  "(?P<ret>(?:const\\s+)?[A-Za-z_][\\w:]*(?:\\s*<[^;{}]*?>)?(?:\\s*[*&])?)",
  "\\s+",
  "(?P<name>[A-Za-z_]\\w*)",
  "\\s*\\(",
  "(?P<args>[^;{}]*?)",
  "\\)",
  "\\s*",
  "(?:const\\s*)?",
  "(?:noexcept\\s*)?",
  "(?:override\\s*)?",
  "(?:final\\s*)?",
  "(?:=\\s*0\\s*)?",
  "(?:=\\s*default\\s*)?",
  "(?:=\\s*delete\\s*)?",
  "\\s*[;{]"
)

## Parse a single header file via the regex walker.
parse_header_methods <- function(header_path) {
  text <- paste(readLines(header_path, warn = FALSE, encoding = "UTF-8"),
                collapse = "\n")
  text <- strip_comments(text)
  chunks <- join_decls(text)
  out <- list()
  header_basename <- basename(header_path)
  for (chunk in chunks) {
    if (!grepl("(", chunk, fixed = TRUE)) next
    if (startsWith(chunk, "typedef")) next
    if (startsWith(chunk, "using ")) next
    if (startsWith(chunk, "class ")) next
    if (startsWith(chunk, "struct ")) next
    if (startsWith(chunk, "namespace")) next
    if (startsWith(chunk, "template")) {
      m <- regexpr("^template\\s*<[^>]*>\\s*", chunk, perl = TRUE)
      if (m > 0L) {
        chunk <- substring(chunk, m + attr(m, "match.length"))
      }
    }
    if (startsWith(chunk, "friend")) next
    if (grepl("= delete", chunk, fixed = TRUE)) next

    cap <- regexpr_named(METHOD_RE, chunk)
    if (is.null(cap)) next
    name <- cap$name
    if (startsWith(name, "~")) next
    if (name %in% c("CryptoContextImpl", "BinFHEContext", "Plaintext",
                    "Ciphertext", "PublicKey", "PrivateKey", "KeyPair",
                    "EvalKey")) {
      next  # constructor-like
    }
    if (name == "operator" || startsWith(name, "operator")) next

    ret_type <- trimws(cap$ret)
    arg_str <- trimws(cap$args)
    arg_pieces <- split_cpp_args(arg_str)
    args <- list()
    ok <- TRUE
    for (piece in arg_pieces) {
      if (piece == "" || piece == "void") next
      parsed <- parse_cpp_arg(piece)
      if (is.null(parsed)) { ok <- FALSE; break }
      args[[length(args) + 1L]] <- parsed
    }
    if (!ok) next

    out[[length(out) + 1L]] <- list(
      name        = name,
      kind        = "method",
      return_type = cpp_type_class(ret_type),
      args        = args,
      header_file = header_basename
    )
  }
  out
}

## Helper: PCRE named-group capture. Returns a named list of the
## captured groups, or NULL if the regex doesn't match.
regexpr_named <- function(pattern, text) {
  m <- regexpr(pattern, text, perl = TRUE)
  if (m == -1L) return(NULL)
  starts <- attr(m, "capture.start")
  lens   <- attr(m, "capture.length")
  if (is.null(starts)) return(NULL)
  names_ <- attr(m, "capture.names")
  out <- setNames(
    lapply(seq_along(names_), function(i) {
      substring(text, starts[1L, i], starts[1L, i] + lens[1L, i] - 1L)
    }),
    names_
  )
  out
}

## Split a C++ argument list, respecting < >, ( ), { }.
split_cpp_args <- function(arg_str) {
  if (arg_str == "") return(character())
  chars <- strsplit(arg_str, "", fixed = TRUE)[[1]]
  parts <- character()
  depth <- 0L
  current <- character()
  for (ch in chars) {
    if (ch %in% c("<", "(", "{", "[")) {
      depth <- depth + 1L
      current <- c(current, ch)
    } else if (ch %in% c(">", ")", "}", "]")) {
      depth <- depth - 1L
      current <- c(current, ch)
    } else if (ch == "," && depth == 0L) {
      parts <- c(parts, trimws(paste(current, collapse = "")))
      current <- character()
    } else {
      current <- c(current, ch)
    }
  }
  if (length(current) > 0L) {
    parts <- c(parts, trimws(paste(current, collapse = "")))
  }
  parts[nzchar(parts)]
}

## Parse 'const Foo<T>& name = default' into a schema dict (named list).
parse_cpp_arg <- function(piece) {
  p <- trimws(piece)
  if (p == "") return(NULL)

  ## Split off default at top-level '='.
  default_str <- NULL
  chars <- strsplit(p, "", fixed = TRUE)[[1]]
  depth <- 0L
  eq_idx <- -1L
  for (i in seq_along(chars)) {
    ch <- chars[i]
    if (ch %in% c("<", "(", "{", "[")) depth <- depth + 1L
    else if (ch %in% c(">", ")", "}", "]")) depth <- depth - 1L
    else if (ch == "=" && depth == 0L) { eq_idx <- i; break }
  }
  if (eq_idx > 0L) {
    default_str <- trimws(paste(chars[(eq_idx + 1L):length(chars)], collapse = ""))
    p <- trimws(paste(chars[1:(eq_idx - 1L)], collapse = ""))
  }

  ## Strip trailing array brackets.
  p <- sub("\\[\\s*\\d*\\s*\\]$", "", p, perl = TRUE)
  p <- trimws(p)

  ## Identify name as the trailing identifier.
  name_match <- regmatches(p, regexpr("[A-Za-z_]\\w*\\s*$", p, perl = TRUE))
  if (length(name_match) == 0L) return(NULL)
  name <- trimws(name_match)
  type_str <- trimws(substring(p, 1L, nchar(p) - nchar(name_match)))

  type_class <- cpp_type_class(type_str)
  d <- cpp_default_class(default_str)
  out <- list(name = name, type_class = type_class, default_class = d$class)
  if (d$class != "none") out$default_value <- d$value
  out
}

## Strip leading 'const ', trailing '&' / '*'.
strip_const_ref <- function(t) {
  t <- trimws(t)
  repeat {
    new <- t
    if (startsWith(new, "const ")) new <- trimws(substring(new, 7L))
    if (endsWith(new, "&")) new <- trimws(substring(new, 1L, nchar(new) - 1L))
    if (endsWith(new, "*")) new <- trimws(substring(new, 1L, nchar(new) - 1L))
    if (identical(new, t)) return(t)
    t <- new
  }
}

## Map a (stripped) C++ type token to a harness type_class symbol.
cpp_type_class <- function(t) {
  if (is.null(t) || t == "") return("any")
  t <- trimws(t)
  raw <- t
  t <- strip_const_ref(t)

  ## Ciphertext / Plaintext / key types
  if (grepl("^(Const)?Ciphertext\\s*<.*>$", t, perl = TRUE)) return("Ciphertext")
  if (t %in% c("ConstPlaintext", "Plaintext")) return("Plaintext")
  if (grepl("^(Const)?Plaintext\\s*<.*>$", t, perl = TRUE)) return("Plaintext")
  if (grepl("^PublicKey\\s*<.*>$", t, perl = TRUE)) return("PublicKey")
  if (t == "PublicKey") return("PublicKey")
  if (grepl("^PrivateKey\\s*<.*>$", t, perl = TRUE)) return("PrivateKey")
  if (t == "PrivateKey") return("PrivateKey")
  if (grepl("^EvalKey\\s*<.*>$", t, perl = TRUE)) return("EvalKey")
  if (t == "EvalKey") return("EvalKey")
  if (grepl("^KeyPair\\s*<.*>$", t, perl = TRUE) || t == "KeyPair") return("KeyPair")
  if (grepl("^EvalKeyMap", t, perl = TRUE) || t == "EvalKeyMap") return("EvalKeyMap")

  ## Vectors
  m <- regmatches(t, regexec("^std::vector\\s*<\\s*(.+)\\s*>$", t, perl = TRUE))[[1]]
  if (length(m) >= 2L) {
    inner <- trimws(m[2])
    inner_clean <- strip_const_ref(inner)
    if (inner_clean %in% INT_VECTOR_INNER) return("int_vector")
    if (inner_clean == "double") return("double_vector")
    if (startsWith(inner_clean, "std::complex")) return("complex_vector")
    ic <- cpp_type_class(inner_clean)
    if (ic %in% S7_CLASS_NAMES) return(paste0("vector_of:", ic))
    return("vector")
  }

  ## shared_ptr<Parm...> with nullptr default → optional:CryptoParameters
  m <- regmatches(t, regexec("^std::shared_ptr\\s*<\\s*(.+)\\s*>$", t, perl = TRUE))[[1]]
  if (length(m) >= 2L) {
    inner <- trimws(m[2])
    if (grepl("Parm", inner, fixed = TRUE) || grepl("CryptoParameters", inner, fixed = TRUE)) {
      return("optional:CryptoParameters")
    }
    return(paste0("shared_ptr:", inner))
  }

  ## std::string
  if (t %in% c("std::string", "string")) return("string")
  ## callback
  if (startsWith(t, "std::function<")) return("callback")
  ## ostream / istream
  if (t == "std::ostream") return("ostream")
  if (t == "std::istream") return("istream")
  ## Scalars
  if (t %in% INT_C_TYPES) return("int_scalar")
  if (t == "double") return("double_scalar")
  if (t == "bool") return("bool_scalar")
  if (t == "void") return("void")
  ## std::complex<double>
  if (startsWith(t, "std::complex")) return("complex_scalar")
  ## Enums and other named types
  if (t %in% ENUM_NAMES) return(paste0("enum:", t))
  raw
}

## Map a C++ default literal to (default_class, default_value).
cpp_default_class <- function(default_str) {
  if (is.null(default_str)) return(list(class = "none", value = NULL))
  s <- trimws(default_str)
  if (s == "") return(list(class = "none", value = NULL))
  if (s == "nullptr" || s == "NULL") return(list(class = "null", value = NULL))
  if (s == "true") return(list(class = "bool_literal", value = TRUE))
  if (s == "false") return(list(class = "bool_literal", value = FALSE))
  if (grepl("^-?\\d+(?:[uUlL]+)?$", s, perl = TRUE)) {
    cleaned <- sub("[uUlL]+$", "", s, perl = TRUE)
    val <- suppressWarnings(as.integer(cleaned))
    if (is.na(val)) return(list(class = "non_constant", value = s))
    return(list(class = "int_literal", value = val))
  }
  if (grepl("^-?\\d+\\.\\d*[fFlL]?$|^-?\\d+\\.\\d*[eE][+-]?\\d+$", s, perl = TRUE)) {
    cleaned <- sub("[fFlL]+$", "", s, perl = TRUE)
    val <- suppressWarnings(as.numeric(cleaned))
    if (is.na(val)) return(list(class = "non_constant", value = s))
    return(list(class = "double_literal", value = val))
  }
  if (startsWith(s, "\"") && endsWith(s, "\"")) {
    return(list(class = "string_literal", value = substring(s, 2L, nchar(s) - 1L)))
  }
  if (s %in% c("{}", "[]")) return(list(class = "empty_vector", value = list()))
  list(class = "non_constant", value = s)
}

parse_output_arg <- function(args) {
  if (length(args) == 0L) return(DEFAULT_OUTPUT)
  for (i in seq_along(args)) {
    if (args[i] == "--output" && i < length(args)) return(args[i + 1L])
    if (startsWith(args[i], "--output=")) {
      return(sub("^--output=", "", args[i]))
    }
  }
  DEFAULT_OUTPUT
}

if (sys.nframe() == 0L) {
  main(commandArgs(trailingOnly = TRUE))
}
