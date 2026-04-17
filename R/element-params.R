## OPENFHE PYTHON SOURCE: src/lib/bindings.cpp (ElementParams wrapper)

#' Element Parameters (opaque)
#'
#' Wraps `std::shared_ptr<typename DCRTPoly::Params>` on the C++ side.
#' Used by the `params` argument of CKKS plaintext factories (9105) and
#' returned by `get_element_params()` (9100.2). In Block E 9101 this
#' class ships as scaffolding only: no constructor surface other than
#' wrapping an existing external pointer.
#'
#' @param ptr External pointer (internal use)
#' @export
ElementParams <- new_class("ElementParams",
  parent = OpenFHEObject,
  package = "openfhe"
)

method(print, ElementParams) <- function(x, ...) {
  cli::cli_text("{.cls ElementParams} [{if (ptr_is_valid(x)) 'active' else 'null'}]")
  invisible(x)
}
