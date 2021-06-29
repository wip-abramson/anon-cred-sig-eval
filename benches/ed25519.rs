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
//    let mut group = c.benchmark_group("Ed25519 Key Gen");
    c.bench_function("Ed25519 Key Gen", |b| {
        b.iter(|| {
            let scheme = Ed25519Sha512::new();
            let (public, private) = scheme.keypair(None).unwrap();
        })

    });
}

fn sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519 Sign");

    for size in vec![128, 512, 1024, 16*1024, 64*1024, 128*1024, 256*1024] {
        let data_to_sign = "0".repeat(size);
        let scheme = Ed25519Sha512::new();
        let (public, private) = scheme.keypair(None).unwrap();
        group.bench_function(BenchmarkId::new("Credential Size", size), |b| {
            b.iter(|| {
                let message = sha2::Sha256::digest(data_to_sign.as_bytes()).to_vec();

                let signature = scheme.sign(message.as_slice(), &private).unwrap();

            })
        });
    }


//    println!("verify = {}", res);
}

fn verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Ed25519 Verify");

    for size in vec![128, 512, 1024, 16*1024, 64*1024, 128*1024, 256*1024] {
        let data_to_sign = "0".repeat(size);
        let scheme = Ed25519Sha512::new();
        let (public, private) = scheme.keypair(None).unwrap();
        let message = sha2::Sha256::digest(data_to_sign.as_bytes()).to_vec();

        let signature = scheme.sign(message.as_slice(), &private).unwrap();

        group.bench_function(BenchmarkId::new("Credential Size", size), |b| {
            b.iter(|| {
                let res = scheme.verify(message.as_slice(), signature.as_slice(), &public).unwrap();

            })
        });
    }

}



criterion_group!(
    name = bench_ed25119;
    config = Criterion::default();
    targets = key_gen,sign, verify
);

criterion_main!(bench_ed25119);

