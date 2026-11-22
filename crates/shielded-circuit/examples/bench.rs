//! Measures the circuit: `cargo run --release --locked -p anonymum-shielded-circuit --example bench`

use std::time::Instant;

use anonymum_shielded_circuit::fixtures::*;
use anonymum_shielded_circuit::verifier::*;
use anonymum_shielded_circuit::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use rand_core::OsRng;

fn main() {
    let cs = ConstraintSystem::<Fr>::new_ref();
    ShieldedCircuit::blank(PARAMS).generate_constraints(cs.clone()).unwrap();
    println!("tree depth           {TREE_DEPTH}");
    println!("R1CS constraints     {}", cs.num_constraints());
    println!("witness variables    {}", cs.num_witness_variables());
    println!("public inputs        {}", cs.num_instance_variables() - 1);
    println!("threads              {}", std::thread::available_parallelism().map_or(1, |n| n.get()));

    let start = Instant::now();
    let (pk, vk) = insecure_dev_setup(PARAMS, &mut OsRng).unwrap();
    println!("setup                {:.2} s", start.elapsed().as_secs_f64());
    println!("proving key          {:.1} MiB", pk.compressed_size() as f64 / 1_048_576.0);
    println!("verifying key        {} bytes", vk.compressed_size());
    let pvk = prepare(&vk).unwrap();

    let (mut prove_total, mut prove_max, mut verify_total, mut proofs) = (0.0f64, 0.0f64, 0.0f64, 0u32);
    for case in Case::ALL {
        let built = build(case);
        let start = Instant::now();
        let proof = prove(&pk, built.circuit.clone(), &mut OsRng).unwrap();
        let proving = start.elapsed().as_secs_f64();
        let bytes = encode_proof(&proof);
        let start = Instant::now();
        verify_transaction(&pvk, &bytes, &built.circuit.public, &built.envelope).unwrap();
        let verifying = start.elapsed().as_secs_f64();
        println!("{:<20} prove {proving:.2} s, verify {:.2} ms, proof {} bytes", format!("{case:?}"), verifying * 1e3, bytes.len());
        prove_total += proving;
        prove_max = prove_max.max(proving);
        verify_total += verifying;
        proofs += 1;
    }
    println!("proving, mean        {:.2} s (max {prove_max:.2} s)", prove_total / f64::from(proofs));
    println!("verifying, mean      {:.2} ms (strict decode + sighash + pairing)", verify_total / f64::from(proofs) * 1e3);
}
