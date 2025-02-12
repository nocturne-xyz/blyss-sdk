use actix_web::HttpServer;
use spiral_rs::client::*;
use spiral_rs::params::*;
use spiral_rs::util::*;
use spiral_server::db::loading::*;
use spiral_server::db::sparse_db::SparseDb;
use spiral_server::db::write::unwrap_kv_pairs;
use spiral_server::db::write::update_database;
use spiral_server::error::Error;
use spiral_server::server::*;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::sync::RwLock;
use std::time::Instant;
use uuid::Uuid;

use actix_web::error::PayloadError;
use actix_web::{get, post, web, App};
use base64::{engine::general_purpose, Engine as _};

struct ServerState {
    params: &'static Params,
    db: RwLock<SparseDb>,
    rows: RwLock<Vec<Vec<u8>>>,
    pub_params: RwLock<HashMap<String, PublicParameters<'static>>>,
    params_json: String,
    version: RwLock<u64>,
}

#[post("/update-row")]
async fn update_row(body: web::Bytes, data: web::Data<ServerState>) -> Result<String, Error> {
    let now = Instant::now();

    let mut db_mut = data.db.write().unwrap();
    let largest_update = update_many_items(&data.params, &body, &mut db_mut)?;

    Ok(format!(
        "{{\"status\":\"done updating\", \"loading_time_us\":{}, \"largest_update\":{}}}",
        now.elapsed().as_micros(),
        largest_update
    ))
}

#[post("/write")]
async fn write(body: web::Bytes, data: web::Data<ServerState>) -> Result<String, Error> {
    let now = Instant::now();
    let mut rows_mut = data.rows.write().unwrap();
    let mut db_mut = data.db.write().unwrap();

    let kv_pairs = unwrap_kv_pairs(&body);
    update_database(data.params, &kv_pairs, &mut rows_mut, &mut db_mut);
    let mut version_mut = data.version.write().unwrap();
    *version_mut += 1;

    Ok(format!(
        "{{\"status\":\"done updating\", \"loading_time_us\":{}}}",
        now.elapsed().as_micros(),
    ))
}

#[post("/setup")]
async fn setup(
    body: web::Bytes,
    data: web::Data<ServerState>,
) -> Result<String, actix_web::error::Error> {
    let mut pub_params_map_mut = data.pub_params.write().unwrap();
    assert_eq!(body.len(), data.params.setup_bytes());
    let pub_params = PublicParameters::deserialize(&data.params, &body);

    let uuid = Uuid::new_v4();
    pub_params_map_mut.insert(uuid.to_string(), pub_params);

    Ok(format!("{{\"uuid\":\"{}\"}}", uuid.to_string()))
}

const UUID_V4_STR_BYTES: usize = 36;

async fn private_read_impl(
    body: &[u8],
    data: web::Data<ServerState>,
) -> Result<Vec<u8>, actix_web::error::Error> {
    let db = data.db.read().unwrap();

    let now = Instant::now();
    let result = if data.params.expand_queries {
        // Parse the UUID
        let request_bytes = body;
        assert_eq!(
            request_bytes.len(),
            UUID_V4_STR_BYTES + data.params.query_bytes()
        );
        let uuid_bytes = &request_bytes[..UUID_V4_STR_BYTES];
        let query_bytes = &request_bytes[UUID_V4_STR_BYTES..];
        let uuid = std::str::from_utf8(uuid_bytes).map_err(|_| PayloadError::EncodingCorrupted)?;

        // Look up UUID and get public parameters
        let pub_params_map = data.pub_params.read().unwrap();
        let pub_params = pub_params_map.get(uuid).ok_or(Error::NotFound)?;

        let query = Query::deserialize(&data.params, query_bytes);
        process_query(&data.params, pub_params, &query, &db)
    } else {
        // Here, we get the public parameters in the query
        let request_bytes = body;
        assert_eq!(
            request_bytes.len(),
            data.params.setup_bytes() + data.params.query_bytes()
        );
        let setup_bytes = &request_bytes[..data.params.setup_bytes()];
        let query_bytes = &request_bytes[data.params.setup_bytes()..];

        let pub_params_base = PublicParameters::deserialize(&data.params, setup_bytes);
        let pub_params = &pub_params_base;

        let query = Query::deserialize(&data.params, query_bytes);
        process_query(&data.params, pub_params, &query, &db)
    };
    println!("Query processed. ({} ms)", now.elapsed().as_millis());

    Ok(result)
}

#[post("/private-read")]
async fn private_read(
    body: web::Bytes,
    data: web::Data<ServerState>,
) -> Result<String, actix_web::error::Error> {
    let mut out = Vec::new();
    let mut i = 0;
    let num_chunks = u64::from_le_bytes(body[..8].try_into().unwrap()) as usize;
    i += 8;
    out.extend(u64::to_le_bytes(num_chunks as u64));
    for _ in 0..num_chunks {
        let chunk_len = u64::from_le_bytes(body[i..i + 8].try_into().unwrap()) as usize;
        i += 8;
        let result = private_read_impl(&body[i..i + chunk_len], data.clone()).await?;
        i += chunk_len;

        out.extend(u64::to_le_bytes(result.len() as u64));
        out.extend(result);
    }

    Ok(general_purpose::STANDARD.encode(out))
}

#[get("/meta")]
async fn meta(data: web::Data<ServerState>) -> String {
    let version = data.version.write().unwrap();

    format!(
        r#"{{
            "id": 0,
            "name": "",
            "owner_id": 0,
            "open_access": true,
            "pir_scheme": {},
            "global_version": {}
        }}"#,
        data.params_json, *version
    )
    .to_owned()
}

#[get("/")]
async fn index(data: web::Data<ServerState>) -> String {
    format!("Hello {}!", data.params.poly_len)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let cfg_expand = r#"{
        "n": 2,
        "nu_1": 9,
        "nu_2": 5,
        "p": 256,
        "q2_bits": 22,
        "t_gsw": 7,
        "t_conv": 3,
        "t_exp_left": 5,
        "t_exp_right": 5,
        "instances": 4,
        "db_item_size": 32768
    }"#;

    let args: Vec<String> = env::args().collect();
    let mut port = "8008";
    let mut params_json = "".to_owned();
    let params;
    if args.len() == 4 {
        // [port] [num_items_log2] [item_size_bytes]
        port = &args[1];
        let target_num_log2: usize = args[2].parse().unwrap();
        let item_size_bytes: usize = args[3].parse().unwrap();

        params = get_params_from_store(target_num_log2, item_size_bytes);
    } else if args.len() == 3 {
        // [port] [params.json]
        port = &args[1];
        let inp_params_fname = &args[2];

        params_json = fs::read_to_string(inp_params_fname).unwrap();
        params = params_from_json(&params_json);
    } else {
        // none
        params_json = cfg_expand.to_owned();
        params = params_from_json(cfg_expand);
    }

    let db = SparseDb::new();
    let mut rows = Vec::new();
    for _ in 0..params.num_items() {
        rows.push(Vec::new());
    }

    let server_state = ServerState {
        params: Box::leak(Box::new(params)),
        db: RwLock::new(db),
        rows: RwLock::new(rows),
        pub_params: RwLock::new(HashMap::new()),
        params_json,
        version: RwLock::new(0),
    };
    let state = web::Data::new(server_state);

    println!("Using {} threads", rayon::current_num_threads());
    println!("Listening on {}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(web::PayloadConfig::new(1usize << 32))
            .service(private_read)
            .service(index)
            .service(meta)
            .service(update_row)
            .service(setup)
            .service(write)
    })
    .bind(("localhost", port.parse().unwrap()))
    .unwrap()
    .run()
    .await
}
