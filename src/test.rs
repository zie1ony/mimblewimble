use secp256k1::{
    Secp256k1, ContextFlag,
    key::{SecretKey, PublicKey, ZERO_KEY, ONE_KEY}, 
    pedersen::Commitment,
};
use sha2::{Sha256, Digest};
use rand::thread_rng;

struct Message {
    amount: u64,
    input: Commitment,
    change_output: Commitment,
    nonce: Commitment,
    sum_of_bliding_factors: Commitment
}

struct Response {
    sign: SecretKey,
    nonce: Commitment,
    blinding: Commitment
}

struct TxSignature {
    partials_sum: SecretKey,
    nonces_sum: Commitment
}

struct Transaction {
    inputs: Vec<Commitment>,
    outputs: Vec<Commitment>,
    signature: TxSignature
}

fn blinding(secp: &Secp256k1, i: u64) -> SecretKey {
    let mut sum = ZERO_KEY.clone();
    for _ in 0..i {
        sum.add_assign(secp, &ONE_KEY).unwrap();
    }
    sum
}

fn add_blinding(secp: &Secp256k1, a: &SecretKey, b: &SecretKey) -> SecretKey {
    let mut sum = a.clone();
    sum.add_assign(secp, b).unwrap();
    sum
}


#[test]
fn test_blinding() {
    let mut secp = Secp256k1::with_caps(ContextFlag::Commit);
    secp.randomize(&mut thread_rng());

    let a = blinding(&secp, 6);
    let b = blinding(&secp, 3);

    let expected = blinding(&secp, 9);
    let sum = add_blinding(&secp, &a, &b);
    assert_eq!(sum, expected);
}

#[test]
fn test_transfer() {
	let mut secp = Secp256k1::with_caps(ContextFlag::Commit);
	secp.randomize(&mut thread_rng());

	// Alice input.
	let ali_blinding_key = SecretKey::new(&secp, &mut thread_rng());
    let ali_input = secp.commit(100, ali_blinding_key.clone()).unwrap();

    // Ali change output (CO_ali)
    let ali_change_blinding_key = SecretKey::new(&secp, &mut thread_rng());
    let ali_change = secp.commit(90, ali_change_blinding_key.clone()).unwrap();

    // Ali's nonce.
    let ali_nonce = SecretKey::new(&secp, &mut thread_rng());
    let ali_nonce_commit = secp.commit(0, ali_nonce.clone()).unwrap();

    // Ali's sum of all blinding factors. (rs)
    let ali_blinding_sum = secp.blind_sum(
        vec![ali_change_blinding_key.clone()], 
        vec![ali_blinding_key.clone()]
    ).unwrap();
    let ali_blinding_sum_commit = secp.commit(0, ali_blinding_sum.clone()).unwrap();

    // Message
    let msg = Message {
        amount: 10,
        input: ali_input,
        change_output: ali_change,
        nonce: ali_nonce_commit,
        sum_of_bliding_factors: ali_blinding_sum_commit 
    };

    // Bob's part.

    // Secret key.
    let e: SecretKey = {
        let mut hasher = Sha256::new();
        hasher.input(b"mimblewimble");
        let result: [u8; 32] = hasher.result().into();
        SecretKey::from_slice(&secp, &result).unwrap()
    };

    // Bob's nonce.
    let bob_nonce = SecretKey::new(&secp, &mut thread_rng());
    let bob_nonce_commit = secp.commit(0, bob_nonce.clone()).unwrap();
    
    // Bob's blinding.
    let bob_blinding = SecretKey::new(&secp, &mut thread_rng());
    let bob_blinding_commit = secp.commit(0, bob_blinding.clone()).unwrap();

    // Bob's signature.
    let mut bob_sign = bob_blinding.clone();
    bob_sign.mul_assign(&secp, &e).unwrap();
    bob_sign.add_assign(&secp, &bob_nonce).unwrap();

    // Response
    let resp = Response {
        sign: bob_sign,
        nonce: bob_nonce_commit,
        blinding: bob_blinding_commit
    };

    // Back to Ali.

    // Alice can verify 
    // sign = bob_nonce + e * bob_blinding
    // sign * G = bob_nonce * G + e * bob_blinding * G
    // sign * G = bob_nonce_commit + e * bob_blinding_commit
    {
        // left = sign * G - bob_nonce_commit
        let left = secp.commit_sum(
            vec![secp.commit(0, resp.sign.clone()).unwrap()], 
            vec![resp.nonce]
        ).unwrap().to_pubkey(&secp).unwrap();

        // right = e * bob_blinding_commit
        let mut right = resp.blinding.to_pubkey(&secp).unwrap();
        right.mul_assign(&secp, &e).unwrap();

        assert_eq!(left, right);
    };

    // Alice singnature
    let mut ali_sign = ali_change_blinding_key.clone();
    ali_sign.mul_assign(&secp, &e).unwrap();
    ali_sign.add_assign(&secp, &ali_nonce).unwrap();

    // Sum partial signatures.
    let mut partials_sum = resp.sign.clone();
    partials_sum.add_assign(&secp, &ali_sign).unwrap();

    // Sum nonces.
    let nonces_sum = secp.commit_sum(
        vec![resp.nonce.clone(), ali_nonce_commit.clone()],
        vec![]
    ).unwrap();

    // Transaction Signature
    let signature = TxSignature { partials_sum, nonces_sum };

    // Transaction
    let tx = Transaction {
        inputs: vec![ali_input],
        outputs: vec![ali_change, resp.blinding],
        signature
    };

    // Kernel
    let kernel = secp.commit_sum(tx.inputs, tx.outputs).unwrap();

    // Validate tx
    // tx.signature.partials_sum = tx.signature.nonces_sum + e * kernel
    {
        let left = secp.commit_sum(
            vec![secp.commit(0, tx.signature.partials_sum.clone()).unwrap()], 
            vec![tx.signature.nonces_sum]
        ).unwrap().to_pubkey(&secp).unwrap();

        let mut right = tx.signature.nonces_sum.to_pubkey(&secp).unwrap();
        right.mul_assign(&secp, &e).unwrap();

        assert_eq!(left, right);
    }
}
