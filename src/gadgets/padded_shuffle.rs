use super::value_shuffle;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use std::cmp::{max, min};
use value::{AllocatedValue, Value};

/// Enforces that the values in `y` are a valid reordering of the values in `x`,
/// allowing for padding (zero values) in x that can be omitted in y (or the other way around).
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    mut x: Vec<AllocatedValue>,
    mut y: Vec<AllocatedValue>,
) -> Result<(), R1CSError> {
    let m = x.len();
    let n = y.len();

    // Number of values to be padded on one side of the shuffle
    let pad_count = max(m, n) - min(m, n);
    let mut pad_values = Vec::with_capacity(pad_count);

    for _ in 0..pad_count {
        /*
        // We need three independent variables constrained to be zeroes.
        // We can do that with a single multiplier and two linear constraints for the inputs only.
        // The multiplication constraint is enough to ensure that the third wire is also zero.
        let (q, a, t) = cs.multiply(Scalar::zero().into(), Scalar::zero().into());
        let assignment = Some(Value::zero());
        pad_values.push(AllocatedValue {
            q,
            a,
            t,
            assignment,
        });

        // Make an allocated value whose fields are all zero.
        match x[0].assignment {
            Some(_) => pad_values.push(Value::zero().allocate(cs)?),
            None => pad_values.push(Value::allocate_empty(cs)?),
        }
        */

        // Make an allocated value whose fields are all zero.
        // Note: We could also create the 3 allocated variables using one multiplier 
        // (since the output multiplier is also zero), 
        // but instead we use the `Value` API for clarity (uses two multipliers).
        pad_values.push(Value::zero().allocate(cs)?);
    }

    if m > n {
        y.append(&mut pad_values);
    } else if m < n {
        x.append(&mut pad_values);
    }
    println!("padded x: {:?}", x);
    println!("padded y: {:?}", y);

    value_shuffle::fill_cs(cs, x, y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use value::{ProverCommittable, VerifierCommittable};

    #[test]
    fn padded_shuffle() {
        // Simplest case test - just padding
        // assert!(
        //     padded_shuffle_helper(vec![], vec![zero()]).is_ok()
        // );
        assert!(
            padded_shuffle_helper(vec![zero(), zero()], vec![zero()]).is_ok()
        );

        // k=1, with interspersed empty values
        // assert!(
        //     padded_shuffle_helper(vec![peso(1), zero()], vec![peso(1)]).is_ok()
        // );
        /*
        assert!(
            padded_shuffle_helper(vec![peso(1)], vec![zero(), peso(1)]).is_ok()
        );

        // k=2, with interspersed empty values
        assert!(
            padded_shuffle_helper(vec![peso(1), yuan(4), zero()], vec![peso(1), yuan(4)]).is_ok()
        );
        assert!(
            padded_shuffle_helper(vec![peso(1), zero(), yuan(4)], vec![peso(1), yuan(4)]).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![peso(1), yuan(4)],
                vec![zero(), yuan(4), zero(), peso(1)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(4), zero(), zero(), yuan(4)],
                vec![zero(), yuan(4), yuan(4)]
            )
            .is_ok()
        );

        // k=3, with interspersed empty values
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![yuan(1), yuan(4), peso(8)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![yuan(1), zero(), peso(8), zero(), yuan(4)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![zero(), zero(), yuan(4), yuan(1), peso(8)]
            )
            .is_ok()
        );
        assert!(padded_shuffle_helper(vec![peso(1), yuan(4)], vec![yuan(4), peso(2)]).is_err());
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![
                    zero(),
                    Value {
                        q: 1,
                        a: 0u64.into(),
                        t: 0u64.into()
                    },
                    yuan(4),
                    yuan(1),
                    peso(8)
                ]
            )
            .is_err()
        );
        */
    }

    // Helper functions to make the tests easier to read
    fn yuan(q: u64) -> Value {
        Value {
            q,
            a: 888u64.into(),
            t: 999u64.into(),
        }
    }
    fn peso(q: u64) -> Value {
        Value {
            q,
            a: 666u64.into(),
            t: 777u64.into(),
        }
    }
    fn zero() -> Value {
        Value::zero()
    }

    fn padded_shuffle_helper_no_commitments(inputs: Vec<Value>, outputs: Vec<Value>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let proof = {
            let mut prover_transcript = Transcript::new(b"PaddedShuffleTest");
            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);

            let x = inputs.iter().map(|value| value.allocate(&mut prover)).collect::<Result<_, _>>()?;
            let y = outputs.iter().map(|value| value.allocate(&mut prover)).collect::<Result<_, _>>()?;

            assert!(fill_cs(&mut prover, x, y).is_ok());

            prover.prove()?
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"PaddedShuffleTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let x = (0..inputs.len()).map(|_| Value::allocate_empty(&mut verifier)).collect::<Result<_, _>>()?;
        let y = (0..outputs.len()).map(|_| Value::allocate_empty(&mut verifier)).collect::<Result<_, _>>()?;

        // Verifier adds constraints to the constraint system
        assert!(fill_cs(&mut verifier, x, y).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof)?)
    }

    fn padded_shuffle_helper(input: Vec<Value>, output: Vec<Value>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, input_com, output_com) = {
            let mut prover_transcript = Transcript::new(b"PaddedShuffleTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);
            let (input_com, input_vals) = input.commit(&mut prover, &mut rng);
            let (output_com, output_vals) = output.commit(&mut prover, &mut rng);

            println!("input vars: {:?}", input_vals);
            println!("output vars: {:?}", output_vals);

            assert!(fill_cs(&mut prover, input_vals, output_vals).is_ok());

            let proof = prover.prove()?;
            (proof, input_com, output_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"PaddedShuffleTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let input_vals = input_com.commit(&mut verifier);
        let output_vals = output_com.commit(&mut verifier);

        // Verifier adds constraints to the constraint system
        assert!(fill_cs(&mut verifier, input_vals, output_vals).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof)?)
    }
}
