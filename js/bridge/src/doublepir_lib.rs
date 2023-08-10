use doublepir_rs::{
    database::DbInfo, doublepir::*, matrix::SquishParams, params::Params, pir::PirClient,
    serializer::Serialize,
};
use js_sys::Uint8Array;
use serde_json::{self, Value};
use std::{convert::TryInto, fmt::Write};
use wasm_bindgen::prelude::*;

use sha1::{Digest, Sha1};
use sha2::Sha256;
use web_sys::console;

use aes::{
    cipher::{KeyIvInit, StreamCipher},
    Aes128
};
use ctr::Ctr64BE;
use futures::future;

type Aes128Ctr = Ctr64BE<Aes128>;

const AES_KEY_1: [u8; 16] = [
  0x9c, 0x22, 0x77, 0x85, 0x45, 0xac, 0x22, 0x97, 0x41, 0x90, 0x8e, 0x65, 0x2d,
  0x33, 0x3a, 0x0f
];

const AES_KEY_2: [u8; 16] = [
  0x5f, 0xff, 0xc4, 0x82, 0xc7, 0x2a, 0x85, 0x4a, 0x10, 0x35, 0x9e, 0x9f, 0xa2,
  0xf5, 0xe0, 0x7f
];

fn row_from_key(num_entries: u64, key: &str) -> u64 {
    let buckets_log2 = (num_entries as f64).log2().ceil() as usize;

    let hash = Sha256::digest(key.as_bytes());

    let mut idx = 0;
    for i in 0..buckets_log2 {
        let cond = hash[i / 8] & (1 << (7 - (i % 8)));
        if cond != 0 {
            idx += 1 << (buckets_log2 - i - 1);
        }
    }
    idx
}

fn top_be_bits(data: &[u8], bits: usize) -> u64 {
    let mut idx = 0;
    for i in 0..bits {
        let cond = data[i / 8] & (1 << (7 - (i % 8)));
        if cond != 0 {
            idx += 1 << (bits - i - 1);
        }
    }
    idx
}

fn get_bloom_indices(val: &str, k: usize, log2m: usize) -> Vec<u64> {
    let mut out = Vec::new();
    for k_i in 0..k {
        let val_to_hash = format!("{}", k_i) + val;
        let hash = Sha1::digest(val_to_hash);
        let inp_idx = top_be_bits(&hash, log2m);
        let idx = (inp_idx / 8) * 8 + (7 - (inp_idx % 8));
        out.push(idx);
    }
    out
}

fn bytes_to_hex_upper(data: &[u8]) -> String {
    static CHARS: &'static [u8] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(data.as_ref().len() * 2);

    for &byte in data.iter() {
        s.write_char(CHARS[(byte >> 4) as usize].into()).unwrap();
        s.write_char(CHARS[(byte & 0xf) as usize].into()).unwrap();
    }

    s
}

fn get_key_bloom_indices(key: &str, k: usize, log2m: usize) -> Vec<u64> {
    let hash = Sha1::digest(key);
    let key_str = bytes_to_hex_upper(&hash);

    get_bloom_indices(&key_str, k, log2m)
}

fn extract_result_impl(result: &[u8]) -> bool {
    let val = u64::from_ne_bytes(result.try_into().unwrap());
    val != 0
}

// Container class for a static lifetime DoublePirClient
// Avoids a lifetime in the return signature of bound Rust functions
#[wasm_bindgen]
pub struct DoublePIRApiClient {
    client: &'static mut DoublePirClient,
    index: u64,
    state: Vec<u8>,
    indices: Vec<u64>,
    states: Vec<Vec<u8>>,
    query_plan: Vec<Option<(u64, u64)>>,
}

fn aes_derive_fast(key_idx: u32, ctr: u32, dst: &mut [u8]) {
    let data = vec![0u8; dst.len()];

    let key = if key_idx == 1 { &AES_KEY_1 } else { &AES_KEY_2 };

    let mut ctr_bytes = [0u8; 16];
    (&mut ctr_bytes[12..]).copy_from_slice(&ctr.to_be_bytes());

    let mut cipher = Aes128Ctr::new(key.into(), &ctr_bytes.into());
    cipher.apply_keystream_b2b(&data, dst).expect("aes_derive_fast failed!");
}

fn derive_fast(seed: u32, ctr: u32, dst: &mut [u8]) -> future::Ready<()> {
    if seed == 1 {
        future::ready(aes_derive_fast(1, ctr, dst))
    } else {
        future::ready(aes_derive_fast(2, ctr, dst))
    }
}

#[wasm_bindgen]
impl DoublePIRApiClient {
    pub async fn initialize_client(json_params: Option<String>) -> DoublePIRApiClient {
        console_error_panic_hook::set_once();

        let param_str = json_params.unwrap();
        let v: Value = serde_json::from_str(&param_str).unwrap();

        let num_entries = v["num_entries"].as_str().unwrap().parse::<u64>().unwrap();
        let bits_per_entry = v["bits_per_entry"].as_u64().unwrap() as usize;

        let raw_client = DoublePirClient::with_params_derive_fast(
            &Params::from_string("1024,6.4,92681,92683,32,464"),
            &DbInfo {
                num_entries,
                bits_per_entry: bits_per_entry as u64,
                packing: 8,
                ne: 1,
                x: 1,
                p: 464,
                logq: 32,
                squish_params: SquishParams::default(),
                orig_cols: 92683,
            },
        )
        .await;
        let client = Box::leak(Box::new(raw_client));

        DoublePIRApiClient {
            client,
            index: 0,
            state: Vec::new(),
            indices: Vec::new(),
            states: Vec::new(),
            query_plan: Vec::new(),
        }
    }

    pub fn generate_query(&mut self, _idx_target: u64) -> Box<[u8]> {
        Vec::new().into_boxed_slice()
    }

    pub fn generate_query_batch(&mut self, indices: Vec<u64>) -> Box<[u8]> {
        self.indices = indices.clone();
        console::log_1(&format!("sending: {:?}", indices).into());
        let (queries, client_states, query_plan) = self.client.generate_query_batch(&indices);
        self.states = client_states;
        self.query_plan = query_plan;
        queries.serialize().into_boxed_slice()
    }

    pub async fn generate_query_batch_fast(&mut self, indices: Vec<u64>) -> Uint8Array {
        self.indices = indices.clone();
        console::log_1(&format!("sending: {:?}", indices).into());
        let (queries, client_states, query_plan) = self
            .client
            .generate_query_batch_fast(&indices, derive_fast)
            .await;
        self.states = client_states;
        self.query_plan = query_plan;

        Uint8Array::from(queries.serialize().as_slice())
    }

    pub fn load_hint(&mut self, hint: Box<[u8]>) {
        self.client.load_hint(&hint);
    }

    pub fn decode_response(&self, data: Box<[u8]>) -> Box<[u8]> {
        self.client
            .decode_response(&data, self.index, &self.state)
            .into_boxed_slice()
    }

    pub fn decode_response_batch(&self, data: Box<[u8]>) -> Vec<i32> {
        let mut out = Vec::<i32>::new();
        for (batch_idx, client_state) in self.states.iter().enumerate() {
            let planned_query = self.query_plan[batch_idx];
            if planned_query.is_none() {
                out.push(-1);
                println!("could not get query (batch: {})", batch_idx);
                continue;
            }
            let planned_query = planned_query.unwrap();
            let index_to_query_in_batch = planned_query.1;

            let result = u64::from_ne_bytes(
                self.client
                    .decode_response_impl(&data, index_to_query_in_batch, batch_idx, &client_state)
                    .as_slice()
                    .try_into()
                    .unwrap(),
            );

            out.push(result as i32);
        }
        out
    }

    pub fn get_row(&self, key: &str) -> u64 {
        row_from_key(self.client.num_entries(), key) as u64
    }

    pub fn get_bloom_indices(&self, key: &str, k: usize, log2m: usize) -> Vec<u64> {
        get_key_bloom_indices(key, k, log2m)
    }

    pub fn extract_result(&self, result: &[u8]) -> bool {
        extract_result_impl(result)
    }
}
