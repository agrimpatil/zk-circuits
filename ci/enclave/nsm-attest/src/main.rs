//! nsm-attest: request a genuine attestation document from the Nitro Security
//! Module (NSM) and write the raw COSE_Sign1 CBOR to a file.
//!
//! Usage:
//!   nsm-attest --user-data <hex> --out <path>
//!
//! `--user-data` is the hex-encoded report_data (the 32-byte sha256 digest that
//! tee_build.js computes over the five commitments). It is placed in the NSM
//! `user_data` field, which in the AWS Nitro attestation document surfaces as
//! the verifier-checked user data. The returned document carries the real PCR
//! measurements, the COSE signature, and the AWS CA certificate chain.
//!
//! This binary only works inside a running Nitro Enclave (it talks to /dev/nsm).

use std::fs;
use std::process::exit;

use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut user_data_hex: Option<String> = None;
    let mut out_path: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--user-data" => {
                user_data_hex = args.get(i + 1).cloned();
                i += 2;
            }
            "--out" => {
                out_path = args.get(i + 1).cloned();
                i += 2;
            }
            other => {
                eprintln!("nsm-attest: unknown argument: {other}");
                exit(2);
            }
        }
    }

    let user_data_hex = user_data_hex.unwrap_or_else(|| {
        eprintln!("nsm-attest: --user-data <hex> is required");
        exit(2);
    });
    let out_path = out_path.unwrap_or_else(|| {
        eprintln!("nsm-attest: --out <path> is required");
        exit(2);
    });

    let user_data = decode_hex(&user_data_hex).unwrap_or_else(|e| {
        eprintln!("nsm-attest: invalid --user-data hex: {e}");
        exit(2);
    });

    let fd = nsm_init();
    if fd < 0 {
        eprintln!("nsm-attest: nsm_init failed (fd={fd}); not running inside a Nitro Enclave?");
        exit(1);
    }

    let request = Request::Attestation {
        user_data: Some(ByteBuf::from(user_data)),
        nonce: None,
        public_key: None,
    };

    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => {
            if let Err(e) = fs::write(&out_path, &document) {
                eprintln!("nsm-attest: failed to write {out_path}: {e}");
                exit(1);
            }
            eprintln!("nsm-attest: wrote {} bytes to {out_path}", document.len());
        }
        _ => {
            eprintln!("nsm-attest: unexpected NSM response (no attestation document returned)");
            exit(1);
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("odd-length hex string".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
