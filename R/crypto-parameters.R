## OPENFHE PYTHON SOURCE: src/lib/bindings.cpp (CryptoParameters wrapper)

#' Crypto Parameters (opaque)
#'
#' Wraps `std::shared_ptr<CryptoParametersBase<DCRTPoly>>` on the
#' C++ side. Returned by `get_crypto_parameters(cc)` at 9109
#' (9100.2 getter fleet) and used as an opaque token for RNS-level
#' parameter accessors such as `get_scaling_factor_real`,
#' `get_key_switch_technique`, etc. In 9108 this class ships as
#' scaffolding only: the S7 class definition is in place so that
#' 9109's getter wiring can treat it as already defined, but there
#' is no constructor path from R at 9108 (the wiring lands at
#' 9109 with `get_crypto_parameters`).
#'
#' @param ptr External pointer (internal use)
#' @export
CryptoParameters <- new_class("CryptoParameters",
  parent = OpenFHEObject,
  package = "openfhe"
)

method(print, CryptoParameters) <- function(x, ...) {
  cli::cli_text("{.cls CryptoParameters} [{if (ptr_is_valid(x)) 'active' else 'null'}]")
  invisible(x)
}
