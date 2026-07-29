fn get_verifying_key<'a>() -> Groth16VerifyingKey<'a> {
    Groth16VerifyingKey {
        alpha_g1: G1Affine { x: u256::from_str_radix("6052c6ae90b77a962b3b355cf88cff3f084dfb2a423bd020222acd3e477a214", 16).unwrap(), y: u256::from_str_radix("20d1bbde469078cd777dab43de968f8d5330297c23334b32fe9b78841f64b18", 16).unwrap() },
        beta_g2: G2Affine {
            x: (u256::from_str_radix("1d639914164bbf9f91fe66713fc79afd3d2bf21206b2ac265b3fa94075852760", 16).unwrap(), u256::from_str_radix("1535f84fa5582f2f37628109bc1441ad4911d9d9b22294516260d7e9a9659b38", 16).unwrap()),
            y: (u256::from_str_radix("537bca9350ea24d4599a146d91e6964cbe99de3159b49aa35a496953bd33d28", 16).unwrap(), u256::from_str_radix("278fdcd0f4eda04f64df74dddf21946f69d2eabee79fe18f4189b8782cacad19", 16).unwrap())
        },
        gamma_g2: G2Affine {
            x: (u256::from_str_radix("1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed", 16).unwrap(), u256::from_str_radix("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2", 16).unwrap()),
            y: (u256::from_str_radix("12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa", 16).unwrap(), u256::from_str_radix("90689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b", 16).unwrap())
        },
        delta_g2: G2Affine {
            x: (u256::from_str_radix("10c58eeca2bb26cfa71c9c334d68f8075cf12d73d58ea25b5d0aee17152b31d2", 16).unwrap(), u256::from_str_radix("1e497761c3ab876d78d244ea8dc62bd747bc62de185a628978144d909d4a0462", 16).unwrap()),
            y: (u256::from_str_radix("1fdd7a52499f577befaea5705386a0a5028fbb314d575eb707fff2f93697923e", 16).unwrap(), u256::from_str_radix("15b53a8bc08343ab2a9388050710f5905c3e08d3a35c5dfb53ee0e0984f55ef5", 16).unwrap())
        },
        ic: &[
            G1Affine { x: u256::from_str_radix("a11cbd92460f325207159536d80c9f44582e95462d19ac2c084caac89c25ca0", 16).unwrap(), y: u256::from_str_radix("14f2f0f329e1ee1dd5b5f67adb53683a02b72312bc4175c4ce29578f93a3cb04", 16).unwrap() },
            G1Affine { x: u256::from_str_radix("ea2aee8ab2a7ccd129e35144e1f291401ef18d20cc2ab8523244707ddbc9474", 16).unwrap(), y: u256::from_str_radix("bced3ef5782c6a4278f685e6851503ab10d38e29cd74b98ced8521f5f174a17", 16).unwrap() },
        ],
    }
}

