## R-SPECIFIC: utility functions

#' Get the native integer size of the OpenFHE build
#'
#' Returns 64 or 128 depending on how OpenFHE was compiled.
#' @return integer
#' @export
get_native_int <- function() {
  openfhe_native_int()
}
