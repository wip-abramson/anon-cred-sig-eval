#[macro_use]
extern crate criterion;
#[macro_use]
extern crate ursa;

use ursa::cl::{
    *,
    issuer::Issuer,
    prover::Prover,
    verifier::Verifier,
};

use ursa::bn::BigNumber;
use ursa::signatures::{
    SignatureScheme,
    ed25519::Ed25519Sha512,
    secp256k1::EcdsaSecp256k1Sha256,
    bls::normal,
};
use ursa::bls::*;
use amcl_wrapper::group_elem::GroupElement;
use sha2::Digest;

use criterion::{Criterion, BenchmarkId};

fn key_gen(c: &mut Criterion) {
    let mut group = c.benchmark_group("CL-RSA Key Generation");

    group.sample_size(20);
    for atts in vec![1, 2, 5, 10, 20, 50, 100] {
        group.bench_function(BenchmarkId::new("Attributes", atts), move |b| {
            b.iter(|| {
                let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();

                for x in 0..atts {
                    credential_schema_builder.add_attr(&x.to_string()).unwrap();
                }


                let credential_schema = credential_schema_builder.finalize().unwrap();

                let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
                non_credential_schema_builder.add_attr("link_secret").unwrap();
                let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
                let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
                    Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();
            })
        });

    }

    group.finish()
}

fn credential_issuance(c: &mut Criterion) {
    let mut group = c.benchmark_group("CL-RSA Issue Credential");

    for atts in vec![1, 2, 5, 10, 20, 50, 100] {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();

        for x in 0..atts {
            credential_schema_builder.add_attr(&x.to_string()).unwrap();
        }


        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder.add_attr("link_secret").unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();


        let master_secret = Prover::new_master_secret().unwrap();
        group.bench_function(BenchmarkId::new("Attributes", atts), move |b| {
            b.iter(|| {
                let credential_nonce = new_nonce().unwrap();

                let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();

                let value = "0".repeat(32);
                let attribute_value: BigNumber = BigNumber::from_bytes(sha2::Sha256::digest(value.as_bytes()).to_vec().as_slice()).unwrap();

                credential_values_builder.add_value_hidden("link_secret", &master_secret.value().unwrap()).unwrap();

                for x in 0..atts {
                    credential_values_builder.add_value_known(&x.to_string(), &attribute_value).unwrap();

                }

                let cred_values = credential_values_builder.finalize().unwrap();

                let (blinded_credential_secrets,
                    credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof,
                ) = Prover::blind_credential_secrets(
                    &cred_pub_key,
                    &cred_key_correctness_proof,
                    &cred_values,
                    &credential_nonce,
                ).unwrap();

                let cred_issuance_nonce = new_nonce().unwrap();

                let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
                    "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &cred_issuance_nonce,
                    &cred_values,
                    &cred_pub_key,
                    &cred_priv_key,
                ).unwrap();

                Prover::process_credential_signature(
                    &mut cred_signature,
                    &cred_values,
                    &signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &cred_pub_key,
                    &cred_issuance_nonce,
                    None,
                    None,
                    None,
                ).unwrap();
            })
        });
    }
}



fn credential_issuance_attribute_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("CL-RSA Issue Credential");

    for size in vec![128, 512, 1024, 16*1024, 64*1024, 128*1024, 256*1024] {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();

        credential_schema_builder.add_attr("image").unwrap();



        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder.add_attr("link_secret").unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();


        let master_secret = Prover::new_master_secret().unwrap();
        group.bench_function(BenchmarkId::new("Attribute Size", size), move |b| {
            b.iter(|| {
                let credential_nonce = new_nonce().unwrap();

                let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();

                let value = "0".repeat(size);
                let attribute_value: BigNumber = BigNumber::from_bytes(sha2::Sha256::digest(value.as_bytes()).to_vec().as_slice()).unwrap();

                credential_values_builder.add_value_hidden("link_secret", &master_secret.value().unwrap()).unwrap();


                credential_values_builder.add_value_known("image", &attribute_value).unwrap();



                let cred_values = credential_values_builder.finalize().unwrap();

                let (blinded_credential_secrets,
                    credential_secrets_blinding_factors,
                    blinded_credential_secrets_correctness_proof,
                ) = Prover::blind_credential_secrets(
                    &cred_pub_key,
                    &cred_key_correctness_proof,
                    &cred_values,
                    &credential_nonce,
                ).unwrap();

                let cred_issuance_nonce = new_nonce().unwrap();

                let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
                    "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
                    &blinded_credential_secrets,
                    &blinded_credential_secrets_correctness_proof,
                    &credential_nonce,
                    &cred_issuance_nonce,
                    &cred_values,
                    &cred_pub_key,
                    &cred_priv_key,
                ).unwrap();

                Prover::process_credential_signature(
                    &mut cred_signature,
                    &cred_values,
                    &signature_correctness_proof,
                    &credential_secrets_blinding_factors,
                    &cred_pub_key,
                    &cred_issuance_nonce,
                    None,
                    None,
                    None,
                ).unwrap();
            })
        });
    }
}

fn credential_presentation(c: & mut Criterion) {
    let mut group = c.benchmark_group("CL-RSA Present Proof");

    for atts in vec![1, 2, 5, 10, 20, 50, 100] {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();

        for x in 0..atts {
            credential_schema_builder.add_attr(&x.to_string()).unwrap();
        }


        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder.add_attr("link_secret").unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();


        let master_secret = Prover::new_master_secret().unwrap();

        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();
        let value = "0".repeat(32);
        let attribute_value: BigNumber = BigNumber::from_bytes(sha2::Sha256::digest(value.as_bytes()).to_vec().as_slice()).unwrap();

        credential_values_builder.add_value_hidden("link_secret", &master_secret.value().unwrap()).unwrap();

        for x in 0..atts {
            credential_values_builder.add_value_known(&x.to_string(), &attribute_value).unwrap();

        }

        let cred_values = credential_values_builder.finalize().unwrap();

        let (blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        ).unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        ).unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        ).unwrap();


        group.bench_function(BenchmarkId::new("Attributes", atts), move |b| {
            b.iter(|| {
                let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();

                for x in 0..atts {
                    sub_proof_request_builder.add_revealed_attr(&x.to_string()).unwrap();

                }



                let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
                let mut proof_builder = Prover::new_proof_builder().unwrap();
                proof_builder.add_common_attribute("master_secret").unwrap();
                proof_builder
                    .add_sub_proof_request(
                        &sub_proof_request,
                        &credential_schema,
                        &non_credential_schema,
                        &cred_signature,
                        &cred_values,
                        &cred_pub_key,
                        None,
                        None,
                    ).unwrap();

                let proof_request_nonce = new_nonce().unwrap();
                let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

                let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
                proof_verifier
                    .add_sub_proof_request(
                        &sub_proof_request,
                        &credential_schema,
                        &non_credential_schema,
                        &cred_pub_key,
                        None,
                        None,
                    ).unwrap();
                let is_valid = proof_verifier.verify(&proof, &proof_request_nonce).unwrap();
            })
        });
    }
}

fn credential_presentation_attribute_size(c: & mut Criterion) {
    let mut group = c.benchmark_group("CL-RSA Present Proof");

    for size in vec![128, 512, 1024, 16*1024, 64*1024, 128*1024, 256*1024] {
        let mut credential_schema_builder = Issuer::new_credential_schema_builder().unwrap();

        credential_schema_builder.add_attr("image").unwrap();



        let credential_schema = credential_schema_builder.finalize().unwrap();

        let mut non_credential_schema_builder = NonCredentialSchemaBuilder::new().unwrap();
        non_credential_schema_builder.add_attr("link_secret").unwrap();
        let non_credential_schema = non_credential_schema_builder.finalize().unwrap();
        let (cred_pub_key, cred_priv_key, cred_key_correctness_proof) =
            Issuer::new_credential_def(&credential_schema, &non_credential_schema, false).unwrap();


        let master_secret = Prover::new_master_secret().unwrap();

        let credential_nonce = new_nonce().unwrap();

        let mut credential_values_builder = Issuer::new_credential_values_builder().unwrap();

        let value = "0".repeat(size);
        let attribute_value: BigNumber = BigNumber::from_bytes(sha2::Sha256::digest(value.as_bytes()).to_vec().as_slice()).unwrap();

        credential_values_builder.add_value_hidden("link_secret", &master_secret.value().unwrap()).unwrap();


        credential_values_builder.add_value_known("image", &attribute_value).unwrap();



        let cred_values = credential_values_builder.finalize().unwrap();

        let (blinded_credential_secrets,
            credential_secrets_blinding_factors,
            blinded_credential_secrets_correctness_proof,
        ) = Prover::blind_credential_secrets(
            &cred_pub_key,
            &cred_key_correctness_proof,
            &cred_values,
            &credential_nonce,
        ).unwrap();

        let cred_issuance_nonce = new_nonce().unwrap();

        let (mut cred_signature, signature_correctness_proof) = Issuer::sign_credential(
            "CnEDk9HrMnmiHXEV1WFgbVCRteYnPqsJwrTdcZaNhFVW",
            &blinded_credential_secrets,
            &blinded_credential_secrets_correctness_proof,
            &credential_nonce,
            &cred_issuance_nonce,
            &cred_values,
            &cred_pub_key,
            &cred_priv_key,
        ).unwrap();

        Prover::process_credential_signature(
            &mut cred_signature,
            &cred_values,
            &signature_correctness_proof,
            &credential_secrets_blinding_factors,
            &cred_pub_key,
            &cred_issuance_nonce,
            None,
            None,
            None,
        ).unwrap();


        group.bench_function(BenchmarkId::new("Attribute Size", size), move |b| {
            b.iter(|| {
                let mut sub_proof_request_builder = Verifier::new_sub_proof_request_builder().unwrap();


                sub_proof_request_builder.add_revealed_attr("image").unwrap();





                let sub_proof_request = sub_proof_request_builder.finalize().unwrap();
                let mut proof_builder = Prover::new_proof_builder().unwrap();
                proof_builder.add_common_attribute("master_secret").unwrap();
                proof_builder
                    .add_sub_proof_request(
                        &sub_proof_request,
                        &credential_schema,
                        &non_credential_schema,
                        &cred_signature,
                        &cred_values,
                        &cred_pub_key,
                        None,
                        None,
                    ).unwrap();

                let proof_request_nonce = new_nonce().unwrap();
                let proof = proof_builder.finalize(&proof_request_nonce).unwrap();

                let mut proof_verifier = Verifier::new_proof_verifier().unwrap();
                proof_verifier
                    .add_sub_proof_request(
                        &sub_proof_request,
                        &credential_schema,
                        &non_credential_schema,
                        &cred_pub_key,
                        None,
                        None,
                    ).unwrap();
                let is_valid = proof_verifier.verify(&proof, &proof_request_nonce).unwrap();
            })
        });
    }
}

criterion_group!(
    name = bench_cl;
    config = Criterion::default();
    targets = key_gen, credential_issuance_attribute_size, credential_issuance, credential_presentation, credential_presentation_attribute_size
);

criterion_main!(bench_cl);

