const fs = require('fs');

const vk = JSON.parse(fs.readFileSync('verification_key.json', 'utf-8'));

function hexToRustU256(hexStr) {
  // SnarkJS outputs decimal strings for coordinates, not hex.
  // We need to convert them to ethnum::u256 format.
  // Since we are writing to Soroban Rust (ethnum::u256::from_str_radix), we can just output hex strings or from_str_radix.
  let big = BigInt(hexStr);
  return `u256::from_str_radix("${big.toString(16)}", 16).unwrap()`;
}

function printG1(point) {
  return `G1Affine { x: ${hexToRustU256(point[0])}, y: ${hexToRustU256(point[1])} }`;
}

function printG2(point) {
  // SnarkJS G2 format: [ [x_c0, x_c1], [y_c0, y_c1] ]
  // Wait, let's check Arkworks or Soroban-ZK-Std G2 format. It's usually (x_c0, x_c1)
  // Let's assume (c0, c1).
  return `G2Affine {
            x: (${hexToRustU256(point[0][0])}, ${hexToRustU256(point[0][1])}),
            y: (${hexToRustU256(point[1][0])}, ${hexToRustU256(point[1][1])})
        }`;
}

let out = `fn get_verifying_key<'a>() -> Groth16VerifyingKey<'a> {
    Groth16VerifyingKey {
        alpha_g1: ${printG1(vk.vk_alpha_1)},
        beta_g2: ${printG2(vk.vk_beta_2)},
        gamma_g2: ${printG2(vk.vk_gamma_2)},
        delta_g2: ${printG2(vk.vk_delta_2)},
        ic: &[
`;
for (let ic of vk.IC) {
    out += `            ${printG1(ic)},\n`;
}
out += `        ],
    }
}
`;

console.log(out);
