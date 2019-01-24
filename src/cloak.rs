use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use crate::{merge, range_proof, split};
use shuffle::{padded_shuffle, value_shuffle};
use value::AllocatedValue;

/// Enforces that the outputs are a valid rearrangement of the inputs, following the
/// soundness and secrecy requirements in the spacesuit transaction spec:
/// https://github.com/interstellar/spacesuit/blob/master/spec.md
pub fn cloak<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<AllocatedValue>,
    outputs: Vec<AllocatedValue>,
) -> Result<(), R1CSError> {
    // Merge
    let (merge_in, merge_out) = merge::fill_cs(cs, inputs.clone())?;

    // Split
    let (split_out, split_in) = split::fill_cs(cs, outputs.clone())?;

    // Shuffle 1
    // Check that `merge_in` is a valid reordering of `inputs`
    // when `inputs` are grouped by flavor.
    value_shuffle(cs, inputs, merge_in)?;

    // Shuffle 2
    // Check that `split_in` is a valid reordering of `merge_out`, allowing for
    // the adding or dropping of padding values (quantity = 0) if m != n.
    padded_shuffle(cs, merge_out, split_in)?;

    // Shuffle 3
    // Check that `split_out` is a valid reordering of `outputs`
    // when `outputs` are grouped by flavor.
    value_shuffle(cs, split_out, outputs.clone())?;

    // Range Proof
    // Check that each of the quantities in `outputs` lies in [0, 2^64).
    for output in outputs {
        range_proof(cs, output.quantity(), 64)?;
    }

    Ok(())
}
