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
# Get compiler settings from R
#
CFLAGS=`"${R_HOME}/bin/R" CMD config CFLAGS`
CXXFLAGS=`"${R_HOME}/bin/R" CMD config CXXFLAGS`
LDFLAGS=`"${R_HOME}/bin/R" CMD config LDFLAGS`

export CC=`"${R_HOME}/bin/R" CMD config CC`
export CXX=`"${R_HOME}/bin/R" CMD config CXX17`
export CFLAGS
export CXXFLAGS
export LDFLAGS

R_OPENFHE_PKG_HOME=`pwd`
OPENFHE_SRC_DIR=${R_OPENFHE_PKG_HOME}/inst/openfhe
OPENFHE_INSTALL_DIR=${R_OPENFHE_PKG_HOME}/src/openfhelib

echo ""
echo "CMAKE VERSION: '`${CMAKE_EXE} --version | head -n 1`'"
echo "CC: '${CC}'"
echo "CXX: '${CXX}'"
echo "CFLAGS: '${CFLAGS}'"
echo "CXXFLAGS: '${CXXFLAGS}'"
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

echo ">>> OpenFHE installed to ${OPENFHE_INSTALL_DIR}"

cd ${R_OPENFHE_PKG_HOME}
