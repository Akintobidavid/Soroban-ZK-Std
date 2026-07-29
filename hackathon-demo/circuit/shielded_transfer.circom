pragma circom 2.0.0;

include "node_modules/circomlib/circuits/comparators.circom";

// A simple circuit that proves: balance >= amount
// And outputs public signal `amount` so the smart contract can verify
template ShieldedTransfer() {
    signal input balance; // private
    signal input amount;  // public

    // Enforce balance >= amount
    // We use GreaterEqThan with 64 bits (can handle up to ~1.8e19 stroops, enough for XLM supply)
    component geq = GreaterEqThan(64);
    geq.in[0] <== balance;
    geq.in[1] <== amount;
    geq.out === 1;
}

// amount is public, balance is private
component main {public [amount]} = ShieldedTransfer();
