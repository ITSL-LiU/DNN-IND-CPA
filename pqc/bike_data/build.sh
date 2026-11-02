#!/bin/bash

# Build script for BIKE KEM test programs

set -e

echo "Building BIKE KEM library..."

# Wipe and recreate the build directory so CMake re-detects
# CMAKE_SYSTEM_PROCESSOR fresh -- a stale build dir from a build on a
# different architecture (e.g. x86_64 login node vs aarch64 GH200 compute
# node) would otherwise keep reusing the old, cached processor detection
# and compiler flags.
rm -rf bike-kem/build
mkdir -p bike-kem/build

# Build the BIKE library
cd bike-kem/build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
cd ../..

echo "BIKE library built successfully"

echo ""
echo "Building test programs..."

# Compile the simple version
echo "  Compiling bike_program..."
gcc -O2 -I./bike-kem/include -I./bike-kem/include/internal \
    bike_program.c -o bike_program \
    -L./bike-kem/build -lbike -lm -lstdc++

echo "  Compiling bike_program_advanced..."
# Compile the advanced version
gcc -O2 -I./bike-kem/include -I./bike-kem/include/internal \
    bike_program_advanced.c -o bike_program_advanced \
    -L./bike-kem/build -lbike -lm -lstdc++

echo "  Compiling bike_encap_program..."
# Compile the encapsulation program
gcc -O3 -march=native -I./bike-kem/include -I./bike-kem/include/internal \
    bike_encap_program.c -o bike_encap_program \
    -L./bike-kem/build -lbike -lm -lstdc++

echo "  Compiling bike_program_pke..."
# Compile the PKE program (similar to Kyber and HQC)
gcc -O2 -DSTANDALONE_IMPL=1 -DUSE_SHA3_AND_SHAKE=1 \
    -I./bike-kem/include -I./bike-kem/include/internal -I./bike-kem/src/third_party_src \
    bike_program_pke.c -o bike_program_pke \
    -L./bike-kem/build -lbike -lm -lstdc++

echo ""
echo "Build complete!"
echo ""
echo "Usage:"
echo "  ./bike_program <N> <output_file>"
echo "  ./bike_program_advanced <N> <output_file>"
echo "  ./bike_encap_program <N> <output_file>"
echo "  ./bike_program_pke <N> <output_file>  (PKE version - similar to Kyber/HQC)"
echo ""
echo "Example:"
echo "  ./bike_program 10 test_output"
echo "  ./bike_program_advanced 10 test_output_advanced"
echo "  ./bike_encap_program 10 test_encap"
echo "  ./bike_program_pke 10 test_pke"
