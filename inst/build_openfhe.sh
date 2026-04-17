#!/bin/bash
#
# build_openfhe.sh — Build OpenFHE static libraries from vendored source
#
# Called by configure during R CMD INSTALL.
# Produces: src/openfhelib/ with include/ and lib/ subdirectories.

#
# Detect tools
#
if test -z "${MAKE}"; then MAKE=`which make 2>/dev/null`; fi
if test -z "${MAKE}"; then MAKE=`which /Applications/Xcode.app/Contents/Developer/usr/bin/make 2>/dev/null`; fi

if test -z "${CMAKE_EXE}"; then CMAKE_EXE=`which cmake4 2>/dev/null`; fi
if test -z "${CMAKE_EXE}"; then CMAKE_EXE=`which cmake3 2>/dev/null`; fi
if test -z "${CMAKE_EXE}"; then CMAKE_EXE=`which cmake 2>/dev/null`; fi
if test -z "${CMAKE_EXE}"; then CMAKE_EXE=`which /Applications/CMake.app/Contents/bin/cmake 2>/dev/null`; fi

if test -z "${CMAKE_EXE}"; then
    echo "Could not find 'cmake'!"
    exit 1
fi

: ${R_HOME=`R RHOME`}
if test -z "${R_HOME}"; then
    echo "'R_HOME' could not be found!"
    exit 1
fi

#
# Get compiler settings from R.
#
# Per Writing R Extensions §1.2.4, a package that sets CXX_STD = CXX17 (as
# openfhe does) should use the CXX17* configuration variables rather than
# the default CXX* ones when compiling sub-libraries, so the static OpenFHE
# archives are built with the same toolchain and flags the R package layer
# will use.
#
# Per §1.2.1.1, OpenMP linkage is conveyed by SHLIB_OPENMP_CXXFLAGS (R will
# return an empty string on platforms without OpenMP support). We feed that
# flag into the CMake compile/link lines so the static archives match the
# final DLL's OpenMP ABI, instead of hardcoding -lgomp (explicitly forbidden
# in §1.6.4).
#
CFLAGS=`"${R_HOME}/bin/R" CMD config CFLAGS`
LDFLAGS=`"${R_HOME}/bin/R" CMD config LDFLAGS`

CXX17=`"${R_HOME}/bin/R" CMD config CXX17`
CXX17STD=`"${R_HOME}/bin/R" CMD config CXX17STD`
CXX17FLAGS=`"${R_HOME}/bin/R" CMD config CXX17FLAGS`
CXX17PICFLAGS=`"${R_HOME}/bin/R" CMD config CXX17PICFLAGS`

# OpenMP flag. Preferred source is OPENFHE_OMP_CXXFLAGS exported by the
# parent configure script (which ran the full three-strategy detection).
# If this script is run standalone (no configure), fall back to whatever
# R's Makeconf advertises — empty is a valid answer.
if [ -z "${OPENFHE_OMP_CXXFLAGS+x}" ]; then
    OPENFHE_OMP_CXXFLAGS=`"${R_HOME}/bin/R" CMD config SHLIB_OPENMP_CXXFLAGS 2>/dev/null`
fi

export CC=`"${R_HOME}/bin/R" CMD config CC`
export CXX="${CXX17} ${CXX17STD}"
export CFLAGS
export CXXFLAGS="${CXX17FLAGS} ${CXX17PICFLAGS} ${OPENFHE_OMP_CXXFLAGS}"
export LDFLAGS

R_OPENFHE_PKG_HOME=`pwd`
OPENFHE_SRC_DIR=${R_OPENFHE_PKG_HOME}/inst/openfhe
OPENFHE_INSTALL_DIR=${R_OPENFHE_PKG_HOME}/src/openfhelib

echo ""
echo "CMAKE VERSION: '`${CMAKE_EXE} --version | head -n 1`'"
echo "CC:       '${CC}'"
echo "CXX:      '${CXX}'"
echo "CFLAGS:   '${CFLAGS}'"
echo "CXXFLAGS: '${CXXFLAGS}'"
echo "LDFLAGS:  '${LDFLAGS}'"
echo "OPENFHE_OMP_CXXFLAGS:  '${OPENFHE_OMP_CXXFLAGS}'"
echo ""

#
# Detect ccache for faster rebuilds
#
CCACHE_OPTS=""
CCACHE_EXE=`which ccache 2>/dev/null`
if test -n "${CCACHE_EXE}"; then
    CCACHE_OPTS="-DCMAKE_C_COMPILER_LAUNCHER=${CCACHE_EXE} -DCMAKE_CXX_COMPILER_LAUNCHER=${CCACHE_EXE}"
    echo "Found ccache: ${CCACHE_EXE}"
fi

#
# Common CMake options
#
COMMON_CMAKE_OPTS="
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_POSITION_INDEPENDENT_CODE:bool=ON
    -DBUILD_SHARED:bool=OFF
    -DBUILD_STATIC:bool=ON
    -DBUILD_UNITTESTS:bool=OFF
    -DBUILD_EXAMPLES:bool=OFF
    -DBUILD_BENCHMARKS:bool=OFF
    -DGIT_SUBMOD_AUTO:bool=OFF
    -DCMAKE_INSTALL_PREFIX=${OPENFHE_INSTALL_DIR}
    ${CCACHE_OPTS}
"

# Platform-specific flags
if test "$(uname -s)" = "Darwin"; then
    CMAKE_PLATFORM_OPTS="-DCMAKE_HOST_APPLE:bool=ON"

    # Use R's libomp to avoid dual-libomp crashes.
    # The r_pkg branch patch allows passing OPENMP_LIBRARIES and
    # OPENMP_INCLUDES to override Homebrew/MacPorts auto-detection.
    if test -n "${OPENMP_LIB_DIR}" && test -n "${OPENMP_INC_DIR}"; then
        echo "Using externally specified OpenMP: lib=${OPENMP_LIB_DIR} inc=${OPENMP_INC_DIR}"
        CMAKE_PLATFORM_OPTS="${CMAKE_PLATFORM_OPTS} -DOPENMP_LIBRARIES=${OPENMP_LIB_DIR} -DOPENMP_INCLUDES=${OPENMP_INC_DIR}"
    fi
else
    CMAKE_PLATFORM_OPTS="-G \"Unix Makefiles\""
fi

# ========================================================
# Build OpenFHE (static libraries)
# ========================================================
echo ">>> Building OpenFHE..."
OPENFHE_BUILD_DIR=${OPENFHE_SRC_DIR}/build
mkdir -p ${OPENFHE_BUILD_DIR}
mkdir -p ${OPENFHE_INSTALL_DIR}/lib
mkdir -p ${OPENFHE_INSTALL_DIR}/include
cd ${OPENFHE_BUILD_DIR}

eval ${CMAKE_EXE} .. ${COMMON_CMAKE_OPTS} ${CMAKE_PLATFORM_OPTS} || exit 1

# Build static library targets
${MAKE} OPENFHEcore_static OPENFHEpke_static OPENFHEbinfhe_static || exit 1

echo ">>> OpenFHE built in ${OPENFHE_BUILD_DIR}"

# ========================================================
# Manual install: copy static libs + headers
# ========================================================

# Static libraries (OpenFHE names them *_static.a)
for lib in libOPENFHEcore_static.a libOPENFHEpke_static.a libOPENFHEbinfhe_static.a; do
    found=$(find ${OPENFHE_BUILD_DIR} -name "$lib" -print -quit 2>/dev/null)
    if test -n "$found"; then
        destname=$(echo "$lib" | sed 's/_static//')
        cp "$found" ${OPENFHE_INSTALL_DIR}/lib/${destname}
    else
        echo "ERROR: $lib not found in build directory!"
        exit 1
    fi
done

# Headers: copy from source tree preserving the openfhe/ prefix structure
# that our R bindings expect (e.g. #include "openfhe.h" resolves via -I.../openfhe/pke)
INCDIR=${OPENFHE_INSTALL_DIR}/include/openfhe

for component in core pke binfhe; do
    src_inc=${OPENFHE_SRC_DIR}/src/${component}/include
    if test -d "${src_inc}"; then
        mkdir -p ${INCDIR}/${component}
        cp -R ${src_inc}/* ${INCDIR}/${component}/
    fi
done

# Cereal headers (header-only serialization library)
# cmake install does: install(DIRECTORY cereal/include/ DESTINATION include/openfhe)
# which copies the *contents* of include/ — giving include/openfhe/cereal/cereal.hpp
cp -R ${OPENFHE_SRC_DIR}/third-party/cereal/include/* ${INCDIR}/

# CMake-generated config_core.h
GENERATED_CONFIG=$(find ${OPENFHE_BUILD_DIR} -name "config_core.h" -print -quit 2>/dev/null)
if test -n "${GENERATED_CONFIG}"; then
    cp "${GENERATED_CONFIG}" ${INCDIR}/core/
else
    echo "ERROR: config_core.h not found in build directory!"
    exit 1
fi

#
# CRAN portability patch: R CMD check flags `#pragma clang diagnostic`
# directives as non-portable pragmas (Writing R Extensions §1.6.4 and the
# QC.R pragma scan). Upstream OpenFHE's serial.h and serializable.h guard
# these with `#elif defined __clang__`, which is semantically correct C++
# but invisible to R's static text scanner. Strip the clang-pragma lines
# from the installed headers; the `#elif` branches become empty (valid
# preprocessor) and the shipped source is then CRAN-portable. GCC diagnostic
# pragmas in these files remain — R's scanner accepts them as portable.
#
for hdr in "${INCDIR}/core/utils/serial.h" "${INCDIR}/core/utils/serializable.h"; do
    if test -f "${hdr}"; then
        sed -i.bak -e '/^[[:space:]]*#pragma[[:space:]][[:space:]]*clang[[:space:]][[:space:]]*diagnostic/d' "${hdr}"
        rm -f "${hdr}.bak"
        echo "   stripped clang pragmas from $(basename ${hdr})"
    fi
done

echo ">>> OpenFHE installed to ${OPENFHE_INSTALL_DIR}"

cd ${R_OPENFHE_PKG_HOME}
