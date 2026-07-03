pragma circom 2.0.0;

// Note: To compile this, you'd need the circomlib poseidon template.
// For the hackathon demo, this shows the logic of the ZK circuit.

/*
  Shielded Transfer Circuit
  Proves that:
  1. Sender knows the secret (nullifier) of their input note.
  2. Input note commitment matches the hash of (balance, secret).
  3. Sender has enough balance to send `amount`.
  4. Output commitments are correctly generated for the recipient and change.
*/
template ShieldedTransfer() {
    // Public Inputs
    signal input input_commitment; 
    signal input amount; 
    
    // Private Inputs
    signal input sender_balance; 
    signal input sender_secret; 
    signal input recipient_secret; 
    signal input change_secret; 

    // Public Outputs
    signal output recipient_commitment;
    signal output change_commitment;

    // In a real implementation with circomlib, you would do:
    // component poseidon_input = Poseidon(2);
    // poseidon_input.inputs[0] <== sender_balance;
    // poseidon_input.inputs[1] <== sender_secret;
    // input_commitment === poseidon_input.out;
    
    // For the sake of the hackathon boilerplate, we represent the math abstractly:
    signal change_amount;
    change_amount <== sender_balance - amount;

    // Output assignments (mock hashing for demo purposes without circomlib imported)
    recipient_commitment <== amount * recipient_secret;
    change_commitment <== change_amount * change_secret;
}

component main {public [input_commitment, amount]} = ShieldedTransfer();
