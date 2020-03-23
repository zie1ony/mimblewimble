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
    blinding: Commitment,
    output: Commitment
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

fn commit(secp: &Secp256k1, value: u64, blinding: &SecretKey) -> Commitment {
    secp.commit(value, blinding.clone()).unwrap()
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
	let ali_input_blinding = blinding(&secp, 20);
    let ali_input = commit(&secp, 40, &ali_input_blinding);

    // Ali change output (CO_ali)
    let ali_change_blinding = blinding(&secp, 34);
    let ali_change = commit(&secp, 15, &ali_change_blinding);

    // Check
    {
        let sum_blinding = blinding(&secp, 54);
        let sum = commit(&secp, 55, &sum_blinding);
        assert!(secp.verify_commit_sum(vec![sum], vec![ali_input, ali_change]));
    }

    // // Ali's nonce.
    let ali_nonce = blinding(&secp, 222);
    let ali_nonce_commit = commit(&secp, 0, &ali_nonce);

    // Ali's sum of all blinding factors. (rs)
    let ali_blinding_sum = blinding(&secp, 14);
    let ali_blinding_sum_commit = commit(&secp, 0, &ali_blinding_sum);

    // // Message
    let msg = Message {
        amount: 25,
        input: ali_input,
        change_output: ali_change,
        nonce: ali_nonce_commit,
        sum_of_bliding_factors: ali_blinding_sum_commit 
    };

    // Bob's part.

    // Secret key.
    let e: SecretKey = blinding(&secp, 1000);

    // // Bob's nonce.
    let bob_nonce = blinding(&secp, 777);
    let bob_nonce_commit = commit(&secp, 0, &bob_nonce);
    
    // Bob's blinding.
    let bob_blinding = blinding(&secp, 11);
    let bob_blinding_commit = commit(&secp, 0, &bob_blinding);

    // Bob's signature.
    let mut bob_sign = bob_blinding.clone();
    bob_sign.mul_assign(&secp, &e).unwrap();
    bob_sign.add_assign(&secp, &bob_nonce).unwrap();

    // Check
    assert_eq!(bob_sign, blinding(&secp, 777 + 1000 * 11));

    // Bob's output
    let bob_output = commit(&secp, msg.amount, &bob_blinding);

    // Response
    let resp = Response {
        sign: bob_sign,
        nonce: bob_nonce_commit,
        blinding: bob_blinding_commit,
        output: bob_output
    };

    // Back to Ali.

    // Alice can verify 
    // sign = bob_nonce + e * bob_blinding
    // sign * G = bob_nonce * G + e * bob_blinding * G
    // sign * G = bob_nonce_commit + e * bob_blinding_commit
    {
        let sign = commit(&secp, 0, &resp.sign);
        let left = secp.commit_sum(vec![sign], vec![resp.nonce])
            .unwrap().to_pubkey(&secp).unwrap();
        let mut right = resp.blinding.to_pubkey(&secp).unwrap();
        right.mul_assign(&secp, &e).unwrap();

        assert_eq!(left, right);
    };

    // Alice singnature
    let mut ali_sign = ali_blinding_sum.clone();
    ali_sign.mul_assign(&secp, &e).unwrap();
    ali_sign.add_assign(&secp, &ali_nonce).unwrap();

    // // Sum partial signatures.
    let mut partials_sum = resp.sign.clone();
    partials_sum.add_assign(&secp, &ali_sign).unwrap();

    // // Sum nonces.
    let nonces_sum = secp.commit_sum(
        vec![resp.nonce.clone(), ali_nonce_commit.clone()],
        vec![]
    ).unwrap();

    // Transaction Signature
    let signature = TxSignature { partials_sum, nonces_sum };

    // Transaction
    let tx = Transaction {
        inputs: vec![ali_input],
        outputs: vec![ali_change, resp.output],
        signature
    };

    // Kernel
    let kernel = secp.commit_sum(tx.outputs, tx.inputs).unwrap();
    assert_eq!(kernel, commit(&secp, 0, &blinding(&secp, 25)));

    // Validate tx
    // tx.signature.partials_sum = tx.signature.nonces_sum + e * kernel
    {
        let partials_sum = commit(&secp, 0, &tx.signature.partials_sum);
        let left = secp.commit_sum(
            vec![partials_sum],
            vec![tx.signature.nonces_sum]
        ).unwrap().to_pubkey(&secp).unwrap();
        let mut right = kernel.to_pubkey(&secp).unwrap();
        right.mul_assign(&secp, &e).unwrap();

        assert_eq!(left, right);        
    }
}
