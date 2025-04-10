use std::collections::BTreeSet;
use wasm_bindgen_test::*;
use elliptic_curve::FieldBytes;
use manul::{
    dev::{run_sync, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    signature::Keypair,
};
use rand_core::{OsRng, RngCore};
use crate::{AuxGen, AuxInfo, InteractiveSigning, KeyInit, KeyShare, SchemeParams};
use web_sys::Performance;
use crate::params::k256::ProductionParams112;
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

fn get_performance() -> Option<Performance> {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::window()
            .and_then(|window| window.performance())
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

fn get_time() -> f64 {
    if let Some(perf) = get_performance() {
        perf.now()
    } else {
        #[cfg(target_arch = "wasm32")]
        {
            // Fallback to Date.now() in WASM environment
            js_sys::Date::new_0().get_time()
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            // Fallback to std::time in non-WASM environment
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as f64
        }
    }
}

fn log_time(test_name: &str, start: f64, end: f64) {
    #[cfg(target_arch = "wasm32")]
    {
        web_sys::console::log_1(&format!("{} test took {} ms", test_name, end - start).into());
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        println!("{} test took {} ms", test_name, end - start);
    }
}

// #[wasm_bindgen_test]
fn test_key_init() {
    let start = get_time();
    
    let signers = (0..2).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .iter()
        .map(|signer| {
            let entry_point = KeyInit::<ProductionParams112, TestVerifier>::new(all_ids.clone()).unwrap();
            (*signer, entry_point)
        })
        .collect::<Vec<_>>();

    let result = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points);
    assert!(result.is_ok());
    
    let end = get_time();
    log_time("KeyInit", start, end);
}

#[wasm_bindgen_test]
fn test_interactive_signing() {
    
    let signers = (0..2).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let key_shares = KeyShare::new_centralized(&mut OsRng, &all_ids, None);
    let aux_infos = AuxInfo::new_centralized(&mut OsRng, &all_ids);
    let mut message = FieldBytes::<<ProductionParams112 as SchemeParams>::Curve>::default();
    OsRng.fill_bytes(&mut message);

    let entry_points = signers
        .iter()
        .map(|signer| {
            let id = signer.verifying_key();
            let entry_point = InteractiveSigning::<ProductionParams112, TestVerifier>::new(
                message,
                key_shares[&id].clone(),
                aux_infos[&id].clone(),
            )
            .unwrap();
            (*signer, entry_point)
        })
        .collect::<Vec<_>>();

    let start = get_time();

    let result = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points);
    assert!(result.is_ok());
    
    let end = get_time();
    log_time("InteractiveSigning", start, end);
}

// #[wasm_bindgen_test]
fn test_aux_gen() {
    let start = get_time();
    
    let signers = (0..2).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let entry_points = signers
        .iter()
        .map(|signer| {
            let entry_point = AuxGen::<ProductionParams112, TestVerifier>::new(all_ids.clone()).unwrap();
            (*signer, entry_point)
        })
        .collect::<Vec<_>>();

    let result = run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points);
    assert!(result.is_ok());
    
    let end = get_time();
    log_time("AuxGen", start, end);
}
