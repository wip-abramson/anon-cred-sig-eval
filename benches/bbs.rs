#[macro_use]
extern crate criterion;
#[macro_use]
extern crate bbs;
extern crate amcl_wrapper;
use amcl_wrapper::field_elem::FieldElementVector;
use bbs::prelude::*;
use std::collections::BTreeMap;
//use zmix::signatures::SignatureMessageVector;
use criterion::{Criterion, BenchmarkId};


fn keygen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("BBS+ Key Generation");

    for atts in vec![1, 2, 5, 10, 20, 50, 100, 200, 1000] {
        group.bench_function(BenchmarkId::new("Attributes", atts), move |b| {
            b.iter(|| Issuer::new_keys(atts))
        });
//        c.bench_function(format!("create ps key for {}", atts).as_str(), move |b| {
//            let params = Params::new(format!("create ps key for {}", atts).as_bytes());
//            b.iter(|| ps_keys_generate(atts, &params))
//        });
    }

    group.finish()
}

fn deterministic_keygen_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("BBS+ Deterministic Key Generation");

    let (dpk, sk) = Issuer::new_short_keys(None);
    for atts in vec![1, 2, 5, 10, 20, 50, 100, 200, 1000] {
        group.bench_function(BenchmarkId::new("Attributes", atts), move |b| {
            b.iter(|| dpk.to_public_key(atts).unwrap())
        });
//        c.bench_function(format!("create ps key for {}", atts).as_str(), move |b| {
//            let params = Params::new(format!("create ps key for {}", atts).as_bytes());
//            b.iter(|| ps_keys_generate(atts, &params))
//        });
    }
}



fn full_issuance_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("BBS+ Issue Credential");

    for atts in vec![1, 2, 5, 10, 20, 50, 100] {
        let (pk, sk) = Issuer::new_keys(atts).unwrap();
        let value = "0".repeat(32);

        group.bench_function(BenchmarkId::new("Attributes", atts), |b| {
            b.iter(|| {
                let signing_nonce = Issuer::generate_signing_nonce();

                // TODO Need to add communication time and space complexity


                let link_secret = Prover::new_link_secret();
                let mut blind_messages = BTreeMap::new();
                blind_messages.insert(0, link_secret.clone());
                let (ctx, signature_blinding) =
                    Prover::new_blind_signature_context(&pk, &blind_messages, &signing_nonce).unwrap();


                let mut messages = BTreeMap::new();
                for x in 1..atts {
                    messages.insert(x,SignatureMessage::hash(value.as_bytes()));
                }

                // Send `ctx` to signer
//                let attributes = FieldElementVector::random(atts);


                let blind_signature = Issuer::blind_sign(&ctx, &messages, &sk, &pk, &signing_nonce).unwrap();


                let mut msgs = messages
                    .iter()
                    .map(|(_, m)| m.clone())
                    .collect::<Vec<SignatureMessage>>();
                msgs.insert(0, link_secret.clone());


                Prover::complete_signature(&pk, msgs.as_slice(), &blind_signature, &signature_blinding).unwrap();




            })
        });


    }
    group.finish()
}

fn issuance_attribute_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("BBS+ Issue Credential");

    for size in vec![128, 512, 1024, 16*1024, 64*1024, 128*1024, 256*1024] {
        let (pk, sk) = Issuer::new_keys(2).unwrap();
        let value = "0".repeat(size);

        group.bench_function(BenchmarkId::new("Attribute Size", size), |b| {
            b.iter(|| {
                let signing_nonce = Issuer::generate_signing_nonce();

                // TODO Need to add communication time and space complexity


                let link_secret = Prover::new_link_secret();
                let mut blind_messages = BTreeMap::new();
                blind_messages.insert(0, link_secret.clone());
                let (ctx, signature_blinding) =
                    Prover::new_blind_signature_context(&pk, &blind_messages, &signing_nonce).unwrap();


                let mut messages = BTreeMap::new();

                messages.insert(1,SignatureMessage::hash(value.as_bytes()));


                // Send `ctx` to signer
//                let attributes = FieldElementVector::random(atts);


                let blind_signature = Issuer::blind_sign(&ctx, &messages, &sk, &pk, &signing_nonce).unwrap();


                let mut msgs = messages
                    .iter()
                    .map(|(_, m)| m.clone())
                    .collect::<Vec<SignatureMessage>>();
                msgs.insert(0, link_secret.clone());


                Prover::complete_signature(&pk, msgs.as_slice(), &blind_signature, &signature_blinding).unwrap();




            })
        });


    }
    group.finish()
}


fn bbs_prove_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("BBS+ Present Proof");
    let value = "0".repeat(32);

    for atts in vec![1, 2, 5, 10, 20, 50, 100] {
        ////////////////////////// BBS+ Signatures
        let (pk, sk) = Issuer::new_keys(atts).unwrap();

        let signing_nonce = Issuer::generate_signing_nonce();

        // TODO Need to add communication time and space complexity


        let link_secret = Prover::new_link_secret();
        let mut blind_messages = BTreeMap::new();
        blind_messages.insert(0, link_secret.clone());
        let (ctx, signature_blinding) =
            Prover::new_blind_signature_context(&pk, &blind_messages, &signing_nonce).unwrap();


        let mut messages = BTreeMap::new();
        for x in 1..atts {
            messages.insert(x,SignatureMessage::hash(value.as_bytes()));
        }

        // Send `ctx` to signer
//                let attributes = FieldElementVector::random(atts);


        let blind_signature = Issuer::blind_sign(&ctx, &messages, &sk, &pk, &signing_nonce).unwrap();


        let mut msgs = messages
            .iter()
            .map(|(_, m)| m.clone())
            .collect::<Vec<SignatureMessage>>();
        msgs.insert(0, link_secret.clone());


        let res = Prover::complete_signature(&pk, msgs.as_slice(), &blind_signature, &signature_blinding);

        let signature = res.unwrap();



        group.bench_function( BenchmarkId::new("Attributes", atts), |b| {
            b.iter(|| {

                let revealed_indicies: Vec<usize> = (1..atts).map(|v| v).collect();

                let nonce = Verifier::generate_proof_nonce();
                let proof_request = Verifier::new_proof_request(&revealed_indicies, &pk).unwrap();


                let link_hidden = ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
                    link_secret.clone(),
                    nonce.clone(),
                ));

                let mut proof_messages = vec![
                    link_hidden,
                ];

                for x in 1..atts {
                    proof_messages.push(pm_revealed!(value.as_bytes()));
                }

                let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
                    .unwrap();

                let challenge = Prover::create_challenge_hash(&[pok.clone()], None, &nonce).unwrap();

                let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();

                let verification = Verifier::verify_signature_pok(&proof_request, &proof, &nonce);
            })
        });
    }
    group.finish();
}

fn bbs_prove__size_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("BBS+ Present Proof");
    let value = "0".repeat(32);

    for size in vec![128, 512, 1024, 16*1024, 64*1024, 128*1024, 256*1024] {
        let (pk, sk) = Issuer::new_keys(2).unwrap();

        let signing_nonce = Issuer::generate_signing_nonce();

        // TODO Need to add communication time and space complexity


        let link_secret = Prover::new_link_secret();
        let mut blind_messages = BTreeMap::new();
        blind_messages.insert(0, link_secret.clone());
        let (ctx, signature_blinding) =
            Prover::new_blind_signature_context(&pk, &blind_messages, &signing_nonce).unwrap();


        let mut messages = BTreeMap::new();

        messages.insert(1,SignatureMessage::hash(value.as_bytes()));


        // Send `ctx` to signer
//                let attributes = FieldElementVector::random(atts);


        let blind_signature = Issuer::blind_sign(&ctx, &messages, &sk, &pk, &signing_nonce).unwrap();


        let mut msgs = messages
            .iter()
            .map(|(_, m)| m.clone())
            .collect::<Vec<SignatureMessage>>();
        msgs.insert(0, link_secret.clone());


        let res = Prover::complete_signature(&pk, msgs.as_slice(), &blind_signature, &signature_blinding);

        let signature = res.unwrap();



        group.bench_function( BenchmarkId::new("Attribute Size", size), |b| {
            b.iter(|| {

                let revealed_indicies: Vec<usize> = vec![1];

                let nonce = Verifier::generate_proof_nonce();
                let proof_request = Verifier::new_proof_request(&revealed_indicies, &pk).unwrap();


                let link_hidden = ProofMessage::Hidden(HiddenMessage::ExternalBlinding(
                    link_secret.clone(),
                    nonce.clone(),
                ));

                let mut proof_messages = vec![
                    link_hidden,
                ];


                proof_messages.push(pm_revealed!(value.as_bytes()));


                let pok = Prover::commit_signature_pok(&proof_request, proof_messages.as_slice(), &signature)
                    .unwrap();

                let challenge = Prover::create_challenge_hash(&[pok.clone()], None, &nonce).unwrap();

                let proof = Prover::generate_signature_pok(pok, &challenge).unwrap();

                let verification = Verifier::verify_signature_pok(&proof_request, &proof, &nonce);
            })
        });
    }
    group.finish();
}




criterion_group!(
    name = bench_bbs;
    config = Criterion::default();
    targets = keygen_benchmark, deterministic_keygen_benchmark, full_issuance_benchmark, issuance_attribute_size, bbs_prove_benchmark, bbs_prove__size_benchmark
);

criterion_main!(bench_bbs);
