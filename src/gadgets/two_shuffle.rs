#![allow(non_snake_case)]

use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

pub fn two_shuffle<CS: ConstraintSystem>(
    cs: &mut CS,
    A: Variable,
    B: Variable,
    C: Variable,
    D: Variable,
) -> Result<(), R1CSError> {
    cs.specify_randomized_constraints(move |cs| {
        // Get challenge scalar x
        let x = cs.challenge_scalar(b"shuffle challenge");
        // (A - x)*(B - x) = input_mul
        let (_, _, input_mul) = cs.multiply(A - x, B - x);
        // (C - x)*(D - x) = output_mul
        let (_, _, output_mul) = cs.multiply(C - x, D - x);
        // input_mul - output_mul = 0
        cs.constrain(input_mul - output_mul);

        Ok(())
    })
}

pub fn prove(
    A: Scalar,
    B: Scalar,
    C: Scalar,
    D: Scalar,
) -> Result<
    (
        R1CSProof,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
        CompressedRistretto,
    ),
    R1CSError,
> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut prover_transcript = Transcript::new(b"ShuffleTest");
    // Make a prover instance
    let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);

    // Create commitments and allocate high-level variables for A, B, C, D
    let mut rng = rand::thread_rng();
    let (A_com, A_var) = prover.commit(A, Scalar::random(&mut rng));
    let (B_com, B_var) = prover.commit(B, Scalar::random(&mut rng));
    let (C_com, C_var) = prover.commit(C, Scalar::random(&mut rng));
    let (D_com, D_var) = prover.commit(D, Scalar::random(&mut rng));

    // Add 2-shuffle gadget constraints to the prover's constraint system
    two_shuffle(&mut prover, A_var, B_var, C_var, D_var)?;
    // Create a proof
    let proof = prover.prove()?;

    Ok((proof, A_com, B_com, C_com, D_com))
}

pub fn verify(
    proof: R1CSProof,
    A_com: CompressedRistretto,
    B_com: CompressedRistretto,
    C_com: CompressedRistretto,
    D_com: CompressedRistretto,
) -> Result<(), R1CSError> {
    // Common fields for prover and verifier
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut verifier_transcript = Transcript::new(b"ShuffleTest");
    // Make a verifier instance
    let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

    // Allocate high-level variables for A, B, C, D from commitments
    let A_var = verifier.commit(A_com);
    let B_var = verifier.commit(B_com);
    let C_var = verifier.commit(C_com);
    let D_var = verifier.commit(D_com);

    // Add 2-shuffle gadget constraints to the verifier's constraint system
    two_shuffle(&mut verifier, A_var, B_var, C_var, D_var)?;
    // Verify the proof
    Ok(verifier.verify(&proof)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_shuffle() {
        assert!(two_shuffle_helper(3, 6, 3, 6).is_ok());
        assert!(two_shuffle_helper(3, 6, 6, 3).is_ok());
        assert!(two_shuffle_helper(6, 6, 6, 6).is_ok());
        assert!(two_shuffle_helper(3, 3, 6, 3).is_err());
    }

    fn two_shuffle_helper(A: u64, B: u64, C: u64, D: u64) -> Result<(), R1CSError> {
        let (proof, A_com, B_com, C_com, D_com) = prove(A.into(), B.into(), C.into(), D.into())?;
        verify(proof, A_com, B_com, C_com, D_com)
    }
}
