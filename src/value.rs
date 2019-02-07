use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, Variable, Verifier};
use core::ops::Neg;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use rand::distributions::uniform::{SampleUniform, UniformInt};
use rand::{CryptoRng, Rng};
use std::ops::Add;
use subtle::{Choice, ConditionallyNegatable, ConditionallySelectable};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Value {
    pub q: SignedInteger, // quantity
    pub f: Scalar,        // flavor
}

pub struct CommittedValue {
    pub q: CompressedRistretto,
    pub f: CompressedRistretto,
}

/// Helper struct for ease of working with
/// 2-tuples of variables and assignments
#[derive(Copy, Clone, Debug)]
pub struct AllocatedValue {
    pub q: Variable, // quantity
    pub f: Variable, // flavor
    pub assignment: Option<Value>,
}

/// Represents a variable for quantity, along with its assignment.
#[derive(Copy, Clone, Debug)]
pub struct AllocatedQuantity {
    pub variable: Variable,
    pub assignment: Option<SignedInteger>,
}

/// Represents a signed integer in the range [-(2^64-1) .. 2^64-1]
/// Zero value is represented as SignedInteger::Positive(0)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SignedInteger {
    Positive(u64),
    Negative(u64),
    Zero,
}

impl Value {
    /// Returns a zero quantity with a zero flavor.
    pub fn zero() -> Value {
        Value {
            q: SignedInteger::zero(),
            f: Scalar::zero(),
        }
    }

    /// Creates variables for the fields in `Value`, and packages them in an `AllocatedValue`.
    pub fn allocate<CS: ConstraintSystem>(&self, cs: &mut CS) -> Result<AllocatedValue, R1CSError> {
        let q_u64 = self.q.into();
        let (q_var, f_var, _) = cs.allocate(|| Ok((q_u64, self.f, q_u64 * self.f)))?;

        Ok(AllocatedValue {
            q: q_var,
            f: f_var,
            assignment: Some(*self),
        })
    }

    pub fn allocate_unassigned<CS: ConstraintSystem>(
        cs: &mut CS,
    ) -> Result<AllocatedValue, R1CSError> {
        let (q_var, f_var, _) = cs.allocate(|| {
            Err(R1CSError::GadgetError {
                description: "Tried to allocate variables q_var and f_var from function"
                    .to_string(),
            })
        })?;

        Ok(AllocatedValue {
            q: q_var,
            f: f_var,
            assignment: None,
        })
    }
}

impl AllocatedValue {
    /// Returns a quantity variable with its assignment.
    pub fn quantity(&self) -> AllocatedQuantity {
        AllocatedQuantity {
            variable: self.q,
            assignment: self.assignment.map(|v| v.q),
        }
    }

    // /// Make another `AllocatedValue`, with the same assignment and newly allocated variables.
    pub fn reallocate<CS: ConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<AllocatedValue, R1CSError> {
        match self.assignment {
            Some(value) => value.allocate(cs),
            None => Value::allocate_unassigned(cs),
        }
    }
}

impl SignedInteger {
    pub fn zero() -> Self {
        SignedInteger::Zero
    }

    pub fn to_u64(&self) -> Option<u64> {
        match self {
            SignedInteger::Positive(x) => Some(*x),
            SignedInteger::Negative(_) => None,
            SignedInteger::Zero => Some(0),
        }
    }

    fn to_i128(&self) -> i128 {
        match self {
            SignedInteger::Positive(x) => (*x).into(),
            SignedInteger::Negative(x) => -(*x as i128),
            SignedInteger::Zero => 0,
        }
    }

    fn from_i128_unchecked(x: i128) -> Self {
        let x_is_negative: Choice = (i128::is_negative(x) as u8).into();
        let mut x_abs = x;
        x_abs.conditional_negate(x_is_negative);
        let s = SignedInteger::conditional_select(
            &SignedInteger::Positive(x_abs as u64),
            &SignedInteger::Negative(x_abs as u64),
            x_is_negative,
        );
        let x_is_zero: Choice = (x as u8).into();
        SignedInteger::conditional_select(&SignedInteger::Zero, &s, x_is_zero)
    }
}

impl From<u64> for SignedInteger {
    fn from(u: u64) -> SignedInteger {
        let u_non_zero: Choice = (u as u8).into();
        SignedInteger::conditional_select(
            &SignedInteger::Zero,
            &SignedInteger::Positive(u),
            u_non_zero,
        )
    }
}

impl Into<Scalar> for SignedInteger {
    fn into(self) -> Scalar {
        match self {
            SignedInteger::Positive(x) => x.into(),
            SignedInteger::Negative(x) => Scalar::zero() - Scalar::from(x),
            SignedInteger::Zero => Scalar::zero(),
        }
    }
}

impl Add for SignedInteger {
    type Output = SignedInteger;

    fn add(self, rhs: SignedInteger) -> SignedInteger {
        let sum = self.to_i128() + rhs.to_i128();
        SignedInteger::from_i128_unchecked(sum)
    }
}

impl ConditionallySelectable for SignedInteger {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let val = i128::conditional_select(&a.to_i128(), &b.to_i128(), choice);
        SignedInteger::from_i128_unchecked(val)
    }
}

impl Neg for SignedInteger {
    type Output = SignedInteger;

    fn neg(self) -> SignedInteger {
        match self {
            SignedInteger::Positive(x) => SignedInteger::Negative(x),
            SignedInteger::Negative(x) => SignedInteger::Positive(x),
            SignedInteger::Zero => SignedInteger::Zero,
        }
    }
}

pub trait ProverCommittable {
    type Output;

    fn commit<R: Rng + CryptoRng>(&self, prover: &mut Prover, rng: &mut R) -> Self::Output;
}

impl ProverCommittable for Value {
    type Output = (CommittedValue, AllocatedValue);

    fn commit<R: Rng + CryptoRng>(&self, prover: &mut Prover, rng: &mut R) -> Self::Output {
        let (q_commit, q_var) = prover.commit(self.q.into(), Scalar::random(rng));
        let (f_commit, f_var) = prover.commit(self.f, Scalar::random(rng));
        let commitments = CommittedValue {
            q: q_commit,
            f: f_commit,
        };
        let vars = AllocatedValue {
            q: q_var,
            f: f_var,
            assignment: Some(*self),
        };
        (commitments, vars)
    }
}

impl ProverCommittable for Vec<Value> {
    type Output = (Vec<CommittedValue>, Vec<AllocatedValue>);

    fn commit<R: Rng + CryptoRng>(&self, prover: &mut Prover, rng: &mut R) -> Self::Output {
        self.iter().map(|value| value.commit(prover, rng)).unzip()
    }
}

pub trait VerifierCommittable {
    type Output;
    fn commit(&self, verifier: &mut Verifier) -> Self::Output;
}

impl VerifierCommittable for CommittedValue {
    type Output = AllocatedValue;

    fn commit(&self, verifier: &mut Verifier) -> Self::Output {
        AllocatedValue {
            q: verifier.commit(self.q),
            f: verifier.commit(self.f),
            assignment: None,
        }
    }
}

impl VerifierCommittable for Vec<CommittedValue> {
    type Output = Vec<AllocatedValue>;

    fn commit(&self, verifier: &mut Verifier) -> Self::Output {
        self.iter().map(|value| value.commit(verifier)).collect()
    }
}
