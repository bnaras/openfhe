// R-SPECIFIC: package init + utility functions
#include "openfhe_cpp11.h"

[[cpp11::register]]
int openfhe_native_int() {
#if NATIVEINT == 128
  return 128;
#else
  return 64;
#endif
}
