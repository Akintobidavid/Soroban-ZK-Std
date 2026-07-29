#!/bin/bash
set -e

# Compile circuit
echo "Compiling circuit..."
circom shielded_transfer.circom --r1cs --wasm --sym

# Generate powers of tau locally (faster than downloading for small circuits)
echo "Generating powers of tau..."
npx snarkjs powersoftau new bn128 10 pot10_0000.ptau -v
npx snarkjs powersoftau contribute pot10_0000.ptau pot10_0001.ptau --name="First" -v -e="random text"
npx snarkjs powersoftau prepare phase2 pot10_0001.ptau pot10_final.ptau -v

# Setup
echo "Running Groth16 setup..."
npx snarkjs groth16 setup shielded_transfer.r1cs pot10_final.ptau circuit_0000.zkey
npx snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="1st Contributor" -v -e="random entropy string 12345"
npx snarkjs zkey export verificationkey circuit_final.zkey verification_key.json

echo "Done! Verifying key generated at verification_key.json"
