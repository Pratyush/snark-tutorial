#![deny(unused_import_braces, unused_qualifications, trivial_casts, trivial_numeric_casts)]
#![deny(unused_qualifications, variant_size_differences, stable_features)]
#![deny(non_shorthand_field_patterns, unused_attributes, unused_imports, unused_extern_crates)]
#![deny(renamed_and_removed_lints, stable_features, unused_allocation, unused_comparisons)]
#![deny(unused_must_use, unused_mut, unused_unsafe, private_in_public, unsafe_code)]


// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-377 pairing-friendly elliptic curve.
use algebra::{curves::bls12_377::Bls12_377, fields::bls12_377::fr::Fr};
use algebra::PairingEngine as ConstraintEngine;
use snark::{Circuit, ConstraintSystem, SynthesisError, Variable};
// We're going to use the Groth-Maller 17 proving system.
use snark::gm17::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};


// For randomness (during paramgen and proof generation)
use rand::{Rand, thread_rng};

// For benchmarking
use std::error::Error;

/// MulCircuit is a circuit that checks whether, for a given `a` and `c`,
/// the prover knows `b` such that `a * b = c`.
pub struct MulCircuit<E: ConstraintEngine> {
    a: Option<E::Fr>,
    b: Option<E::Fr>,
    c: Option<E::Fr>,
}

impl<E: ConstraintEngine> MulCircuit<E> {
    pub fn new() -> Self {
        Self { a: None, b: None, c: None, }

    }

    pub fn with_values(a: E::Fr, b: E::Fr, c: E::Fr) -> Self {
        Self { a: Some(a), b: Some(b), c: Some(c), }
    }
}

impl<E: ConstraintEngine> Circuit<E> for MulCircuit<E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // `a` and `c` are public inputs.
        let a: Variable = cs.alloc_input(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let c: Variable = cs.alloc_input(|| "c", || self.c.ok_or(SynthesisError::AssignmentMissing))?;

        // `b` is the secret witness.
        let b: Variable = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;

        cs.enforce(|| format!("a * b = c"), |lc| lc + a, |lc| lc + b, |lc| lc + c);
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // This is probably not cryptographically safe; use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();

    // Create parameters for our circuit
    let params = {
        let c = MulCircuit::<Bls12_377>::new();
        generate_random_parameters(c, rng)?
    };

    let a = Fr::rand(rng);
    let b = Fr::rand(rng);
    let c = a * &b;

    let proof = {
        // Create an instance of our circuit (with the witness)
        let circuit = MulCircuit::with_values(a, b, c);
        // Create a proof with our parameters.
        create_random_proof(circuit, &params, rng)?
    };

    let inputs = [a, c];
    let pvk = prepare_verifying_key(&params.vk);
    assert!(verify_proof(&pvk, &proof, &inputs)?, "proof failed to verify");
    Ok(())
}
