// #![deny(unused_import_braces, unused_qualifications, trivial_casts, trivial_numeric_casts)]
// #![deny(unused_qualifications, variant_size_differences, stable_features)]
// #![deny(non_shorthand_field_patterns, unused_attributes, unused_imports, unused_extern_crates)]
// #![deny(renamed_and_removed_lints, stable_features, unused_allocation, unused_comparisons)]
// #![deny(unused_must_use, unused_mut, unused_unsafe, private_in_public, unsafe_code)]


use std::rc::Rc;

// Bring in some tools for using pairing-friendly curves
// We're going to use the BLS12-381 pairing-friendly elliptic curve.
use algebra::{
    ToConstraintField,
    curves::bls12_381::Bls12_381,
    fields::bls12_381::fr::Fr,
};
use algebra::{
    curves::jubjub::JubJubAffine as JubJub,
    fields::jubjub::fq::Fq,
};


use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use r1cs_std::prelude::*;
use r1cs_std::groups::curves::twisted_edwards::jubjub::JubJubGadget;
use crypto_primitives::{
    crh::{
        pedersen::{
            PedersenCRH, PedersenWindow, 
            constraints::{PedersenCRHGadget, PedersenCRHGadgetParameters}
        },
        FixedLengthCRH,
    },
    merkle_tree::*,
    merkle_tree::constraints::*,
};

// We're going to use the Groth-Maller 17 proving system.
use gm17::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
};




// For randomness (during paramgen and proof generation)
use rand::thread_rng;

// For benchmarking
use std::error::Error;


/// Config for the Pedersen hash function
#[derive(Clone)]
pub struct Window4x256;
impl PedersenWindow for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

type H = PedersenCRH<JubJub, Window4x256>;
type HG = PedersenCRHGadget<JubJub, Fq, JubJubGadget>;

pub struct PedersenMerkleTreeParams;

impl MerkleTreeConfig for PedersenMerkleTreeParams {
    const HEIGHT: usize = 5;
    type H = H;
}

type PedersenMerkleTree = MerkleHashTree<PedersenMerkleTreeParams>;
type PedersenMerkleTreePath = MerkleTreePath<PedersenMerkleTreeParams>;
type PedersenMerkleDigest = MerkleTreeDigest<PedersenMerkleTreeParams>;



/// MulCircuit is a circuit that checks whether, for a given `leaf` and `root`,
/// the prover knows `path` such that `path` is a valid Merkle tree path for `leaf`
/// with respect to `root`.
pub struct PathCheckCircuit {
    /// Parameters for the Pedersen CRH (i.e. the generators).
    params: <H as FixedLengthCRH>::Parameters,
    /// Part of instance or "public input"
    leaf: Option<[u8; 30]>,
    /// Part of instance or "public input"
    root: Option<PedersenMerkleDigest>,
    /// Part of witness or "private input"
    path: PedersenMerkleTreePath,
}

impl PathCheckCircuit {
    pub fn for_setup(params: <H as FixedLengthCRH>::Parameters) -> Self {
        Self { params, leaf: None, root: None, path: PedersenMerkleTreePath::default(), }

    }

    pub fn for_proving(
        params: <H as FixedLengthCRH>::Parameters,
        leaf: [u8; 30],
        root: PedersenMerkleDigest,
        path: PedersenMerkleTreePath,
    ) -> Self {
        Self {
            params,
            leaf: Some(leaf),
            root: Some(root),
            path: path,
        }
    }
}

impl ConstraintSynthesizer<Fr> for PathCheckCircuit {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let Self { params, leaf, root, path } = self;
        // Allocate variable for `self.leaf`.
        let leaf = UInt8::alloc_input_vec(
            &mut cs.ns(|| "Leaf"),
            &leaf.unwrap_or([0u8; 30])
        )?;

        // Allocate variable for `self.root`
        // Recall that the output of the Pedersen hash function is a group element.
        let root = JubJubGadget::alloc_input(
            &mut cs.ns(|| "Digest"),
            || root.ok_or(SynthesisError::AssignmentMissing)
        )?;

        // Allocate Parameters for CRH
        let crh_parameters = PedersenCRHGadgetParameters::alloc(
            &mut cs.ns(|| "Parameters"),
            || Ok(params),
        )?;


        // Allocate Merkle Tree Path
        let path = MerkleTreePathGadget::<_, HG, _>::alloc(
            &mut cs.ns(|| "Path"),
            || Ok(path)
        )?;

        path.check_membership(
            &mut cs.ns(|| "Check membership"),
            &crh_parameters,
            &root,
            &leaf.as_slice(),
        )?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // This is probably not cryptographically safe; use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();


    let crh_parameters = H::setup(rng).unwrap();

    // Create parameters for our circuit
    println!("Performing trusted setup");
    let pp = {
        let c = PathCheckCircuit::for_setup(crh_parameters.clone());
        generate_random_parameters::<Bls12_381, _, _>(c, rng)?
    };
    println!("Done with trusted setup");

    let leaves = [
        [0u8; 30],
        [1u8; 30],
        [2u8; 30],
        [3u8; 30],
        [4u8; 30],
    ];

    println!("\nConstructing Merkle tree");
    let tree = PedersenMerkleTree::new(Rc::new(crh_parameters.clone()), &leaves).unwrap();
    let root = tree.root();
    let leaf = leaves[4];
    // This function returns the membership path when given the index and value
    // of the leaf as input.
    let path = tree.generate_proof(4, &leaf).unwrap();
    // Sanity check that the path is a valid proof of membership
    assert!(path.verify(&crh_parameters, &root, &leaf).unwrap());
    println!("Done constructing Merkle tree");

    println!("\nCreating zkSNARK proof of membership");
    let proof = {
        // Create an instance of our circuit (with the witness)
        let c = PathCheckCircuit::for_proving(crh_parameters.clone(), leaf, root, path);
        // Create a proof with our parameters.
        create_random_proof(c, &pp, rng)?
    };
    println!("Done creating proof of membership");


    // Convert the inputs to field elements, because that is what the verification
    // algorithm knows about.
    let mut leaf_fe = leaf.to_field_elements()?;
    let root_fe = root.to_field_elements()?;
    leaf_fe.extend_from_slice(&root_fe);

    let public_inputs = leaf_fe;
    let pvk = prepare_verifying_key(&pp.vk);
    println!("\nVerifying zkSNARK proof of membership");
    assert!(verify_proof(&pvk, &proof, &public_inputs)?, "proof failed to verify");
    println!("Proof verified!");
    Ok(())
}



