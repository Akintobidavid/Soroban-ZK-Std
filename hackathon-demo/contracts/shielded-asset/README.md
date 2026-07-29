# Shielded Asset Template

A complete, production-ready template for building privacy-preserving, regulatory-compliant assets on Stellar using Soroban and zero-knowledge proofs.

## Architecture

This template utilizes a hybrid off-chain/on-chain architecture. Users generate zero-knowledge proofs locally (or via a relayer) proving they have sufficient funds, and the smart contract verifies these proofs using the Soroban host environment without ever seeing the unencrypted balances.

```text
┌────────────────────────────────────────────┐
│  OFF-CHAIN: ZK Prover (Circom/Noir)        │
│  • Prove: sender_balance ≥ amount          │
│  • Prove: commitments updated correctly    │
│  • Output: proof + encrypted amount        │
└────────────────────────────────────────────┘
                    │
                    ▼
┌────────────────────────────────────────────┐
│  ON-CHAIN: ShieldedTransfer (Soroban)      │
│  • Import: your Soroban-ZK-Std library     │
│  • Verify: BN254 ZK proof                  │
│  • Store: Poseidon2 balance commitments    │
│  • Decrypt: ElGamal viewing key (issuer)   │
└────────────────────────────────────────────┘
```

## Features

- **Private Balances**: Token balances are stored as Poseidon2 commitments on-chain.
- **ZK Transfers**: Groth16 proofs verify that a sender has enough funds to send the transaction, without revealing the balance.
- **Compliance & Auditing**: Issuers (or designated compliance oracles) can use ElGamal viewing keys to decrypt the transaction amounts for regulatory monitoring (e.g., AML/KYC checks), while keeping the data hidden from the public.

## Usage

You can use this template as a starting point for building:
- Private Stablecoins (e.g., Shielded USDC)
- Confidential Real-World Assets (RWAs)
- Dark-pool automated market makers

Make sure you have imported the `soroban-zk-std` library into your `Cargo.toml`.
