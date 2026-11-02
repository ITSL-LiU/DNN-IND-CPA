#!/bin/bash
# setup.sh -- fetch and build the C programs that generate the PQC datasets.
#
#   pqc/kyber        <- git clone of pq-crystals/kyber (reference code)
#   pqc/kyber_data   -> kyber_generate_*, kyber_indcpa_enc*   (make)
#   pqc/bike_data    -> bike_encap_program, bike_program_pke  (build.sh,
#                       clones awslabs/bike-kem into pqc/bike_data/bike-kem)
#   pqc/hqc_data     -> build/hqc_test, build/hqc_kem         (cmake; the HQC
#                       sources must be downloaded manually, see README.md)
#
# Python dependencies are not installed here; see README.md.
set -e  # Exit on error

echo "=============================================="
echo "DNN-IND-CPA Repository Setup"
echo "=============================================="

# Load modules (for supercomputer - comment out if running locally)
#if command -v module &> /dev/null; then
#    echo "Loading modules..."
#    module load GCC/12.3.0
#    module load CMake/3.26.3-GCCcore-12.3.0
#    echo "Modules loaded."
#fi

# Get the script's directory; all C code lives in pqc/
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/pqc"

# 1. Clone Kyber if not present (pqc/kyber_data/Makefile expects it at ../kyber)
echo ""
echo "[1/4] Setting up Kyber..."
if [ ! -d "kyber" ]; then
    git clone https://github.com/pq-crystals/kyber.git
    echo "Kyber cloned."
else
    echo "Kyber already exists, skipping clone."
fi

# Build Kyber programs
echo "Building Kyber programs..."
cd kyber_data
make clean 2>/dev/null || true
make
cd ..
echo "Kyber build complete."

# 2. Clone and build BIKE
echo ""
echo "[2/4] Setting up BIKE..."
cd bike_data
if [ ! -d "bike-kem" ]; then
    git clone https://github.com/awslabs/bike-kem.git
    echo "BIKE cloned."
else
    echo "BIKE already exists, skipping clone."
fi

chmod +x build.sh
./build.sh
cd ..
echo "BIKE build complete."

# 3. Build HQC
echo ""
echo "[3/4] Setting up HQC..."
cd hqc_data
if [ ! -d "hqc-v5.0.0" ] && [ ! -d "build" ]; then
    echo "Warning: HQC source not found. Please download HQC manually from:"
    echo "  https://pqc-hqc.org/implementation.html"
    echo "Skipping HQC build."
else
    # Wipe and recreate so CMake re-detects CMAKE_SYSTEM_PROCESSOR fresh --
    # see bike_data/build.sh for why a stale cross-architecture build dir
    # is a problem here too.
    rm -rf build
    cmake -B build -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    echo "HQC build complete."
fi
cd ..

# 4. Create data directory (at the repository root)
echo ""
echo "[4/4] Creating data directory..."
mkdir -p "$SCRIPT_DIR/data"
echo "Data directory ready."

echo ""
echo "=============================================="
echo "Setup complete!"
echo "=============================================="
echo ""
echo "Next steps (from the repository root, see README.md):"
echo "  1. python datagen/generate_data.py single_alg configs/config.json kyber512 data/"
echo "  2. python training/ind_cpa.py configs/config.json data/kyber512_random data/kyber512_nonrandom"
