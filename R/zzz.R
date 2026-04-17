## R-SPECIFIC: package load hooks

.onLoad <- function(libname, pkgname) {
  S7::methods_register()

  ns <- parent.env(environment())

  # S3 Ops handler for Ciphertext (and subclasses via class vector)
  registerS3method("Ops", "openfhe::Ciphertext", .openfhe_Ops_handler,
                   envir = ns)

  # Ensure openfhe wins Ops dispatch against Matrix and other S3 classes
  if (getRversion() >= "4.3.0") {
    registerS3method("chooseOpsMethod", "openfhe::Ciphertext",
                     .openfhe_chooseOpsMethod, envir = ns)
  }
}
