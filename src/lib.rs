use std::time::{ Duration, SystemTime, UNIX_EPOCH };

use wasm_bindgen::prelude::*;

extern crate console_error_panic_hook;
use std::panic;

use authdecode::{
    backend::{
        halo2,
        halo2::{
            prover::Prover as Halo2ProverBackend,
            verifier::Verifier as Halo2VerififerBackend,
            onetimesetup::OneTimeSetup,
        },
    },
    encodings::{ ActiveEncodings, Encoding, FullEncodings, ToActiveEncodings },
    prover::{
        backend::Backend as ProverBackend,
        error::ProverError,
        prover::{ ProofInput, Prover },
        InitData,
        ToInitData,
    },
    utils::{ choose, u8vec_to_boolvec },
    verifier::verifier::Verifier,
};

use std::env;
use tracing_subscriber::{ fmt::format::FmtSpan, EnvFilter };
use hex::encode;
use num::BigUint;
use rand::{ Rng, SeedableRng };
use rand_chacha::ChaCha12Rng;
use web_time::{ Instant };

const PLAINTEXT_SIZE: usize = 1000;

struct DummyEncodingsVerifier {}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(a: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()));
}

impl authdecode::prover::EncodingVerifier for DummyEncodingsVerifier {
    fn init(&self, init_data: InitData) {}

    fn verify(
        &self,
        _encodings: &FullEncodings
    ) -> Result<(), authdecode::prover::EncodingVerifierError> {
        Ok(())
    }
}

#[wasm_bindgen]
pub fn work() {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let window = web_sys::window().expect("should have a window in this context");
    let performance = window.performance().expect("performance should be available");

    tracing_wasm::set_as_global_default();

    console_log!("the current time (in ms) is {}", performance.now());
    performance.mark("beginauthdecode");

    let mut rng = ChaCha12Rng::from_seed([0; 32]);

    let plaintext: Vec<u8> = core::iter
        ::repeat_with(|| rng.gen::<u8>())
        .take(PLAINTEXT_SIZE)
        .collect();

    let full_encodings: Vec<[u128; 2]> = core::iter
        ::repeat_with(|| rng.gen::<[u128; 2]>())
        .take(PLAINTEXT_SIZE * 8)
        .collect();
    let full_encodings = full_encodings
        .into_iter()
        .map(|pair| {
            [Encoding::new(BigUint::from(pair[0])), Encoding::new(BigUint::from(pair[1]))]
        })
        .collect::<Vec<_>>();
    let full_encodings = FullEncodings::new(full_encodings);

    console_log!("plaintext: {:x?}", plaintext);

    let active_encodings = full_encodings.encode(&u8vec_to_boolvec(&plaintext));

    let params = OneTimeSetup::params();
    let proving_key = OneTimeSetup::proving_key(params.clone());
    let verification_key = OneTimeSetup::verification_key(params);

    let h2proverBackend = Halo2ProverBackend::new(proving_key);
    let h2verifierBackend = Halo2VerififerBackend::new(verification_key);

    let prover = Prover::new(Box::new(h2proverBackend));
    let verifier = Verifier::new(Box::new(h2verifierBackend));

    let (prover, commitments) = prover.commit(vec![(plaintext, active_encodings)]).unwrap();

    let (verifier, verification_data) = verifier
        .receive_commitments(
            commitments,
            vec![full_encodings.clone()],
            InitData::new(vec![1u8; 100])
        )
        .unwrap();

    let prover = prover.check(verification_data, DummyEncodingsVerifier {}).unwrap();

    let (prover, proof_sets) = prover.prove().unwrap();

    let verifier = verifier.verify(proof_sets).unwrap();

    performance.mark("endauthdecode");

    performance.measure_with_start_mark_and_end_mark(
        "measureauthdecode",
        "beginauthdecode",
        "endauthdecode"
    );

    for item in performance.get_entries_by_name("measureauthdecode").iter() {
        console_log!("{:?}", item);
    }
}

fn perf_to_system(amt: f64) -> SystemTime {
    let secs = (amt as u64) / 1_000;
    let nanos = (((amt as u64) % 1_000) as u32) * 1_000_000;
    UNIX_EPOCH + Duration::new(secs, nanos)
}
