use ax_server::tls_rustls::RustlsConfig;
use axum::{
    extract::{Json, State},
    routing::post,
    Router,
};
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

// ============================================================
// 🔐 보안 상수 (오토거탐 클라이언트와 동일하게 설정)
// ============================================================
const AES_KEY: &[u8; 32] = b"P1@n3tM@cr0_S3cur3K3y_2026!xYz9Q";
const HMAC_SECRET: &[u8] = b"hM@c_Pl4n3t_S1gn@tur3_K3y_2026!!";
const TIMESTAMP_TOLERANCE_SECS: i64 = 60;

// 암호화/복호화 및 서명 모듈
mod crypto {
    use aes_gcm::{
        aead::{Aead, KeyInit, OsRng},
        AeadCore, Aes256Gcm,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use hmac::{digest::KeyInit as HmacKeyInit, Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<String, String> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, plaintext.as_bytes()).map_err(|e| e.to_string())?;
        let mut combined = nonce.to_vec();
        combined.extend_from_slice(&ct);
        Ok(B64.encode(&combined))
    }

    pub fn decrypt(encrypted_b64: &str, key: &[u8; 32]) -> Result<String, String> {
        let combined = B64.decode(encrypted_b64).map_err(|e| e.to_string())?;
        if combined.len() < 12 { return Err("Invalid ciphertext".into()); }
        let (nonce_bytes, ct) = combined.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let pt = cipher.decrypt(aes_gcm::Nonce::from_slice(nonce_bytes), ct)
            .map_err(|_| "Decryption failed".to_string())?;
        String::from_utf8(pt).map_err(|e| e.to_string())
    }

    pub fn sign(data: &str, secret: &[u8]) -> String {
        let mut mac = <HmacSha256 as HmacKeyInit>::new_from_slice(secret).unwrap();
        mac.update(data.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn verify_signature(data: &str, sig: &str, secret: &[u8]) -> bool {
        let expected = sign(data, secret);
        expected == sig
    }

    pub fn generate_session_token() -> String {
        use rand::Rng;
        let bytes: [u8; 32] = rand::thread_rng().gen();
        hex::encode(bytes)
    }
}

// ============================================================
// 데이터 구조체
// ============================================================
#[derive(Clone)]
struct AppState {
    db: MySqlPool,
    sessions: Arc<Mutex<HashMap<String, String>>>, // user_id -> session_token
}

#[derive(Deserialize)]
struct EncryptedRequest {
    payload: String,
    signature: String,
    timestamp: i64,
}

#[derive(Serialize)]
struct EncryptedResponse {
    payload: String,
    signature: String,
}

#[derive(Deserialize)]
struct LoginRequestInner {
    user_id: String,
    #[allow(dead_code)]
    program: Option<String>,
}

#[derive(Serialize)]
struct LoginResponseInner {
    status: String,
    session_token: Option<String>,
    message: Option<String>,
    is_login: i8,
}

#[derive(Deserialize)]
struct HeartbeatRequestInner {
    user_id: String,
    #[allow(dead_code)]
    program: Option<String>,
}

#[derive(Serialize)]
struct HeartbeatResponseInner {
    status: String,
    action: Option<String>,
}

// ============================================================
// 유틸리티 함수
// ============================================================
fn encrypt_response<T: Serialize>(data: &T) -> EncryptedResponse {
    let json_str = serde_json::to_string(data).unwrap();
    let encrypted = crypto::encrypt(&json_str, AES_KEY).unwrap();
    let signature = crypto::sign(&encrypted, HMAC_SECRET);
    EncryptedResponse { payload: encrypted, signature }
}

// ============================================================
// 핸들러
// ============================================================

async fn login_handler(
    State(state): State<AppState>,
    Json(req): Json<EncryptedRequest>,
) -> Json<EncryptedResponse> {
    // 1. 타임스탬프 검증
    let now = Utc::now().timestamp();
    if (now - req.timestamp).abs() > TIMESTAMP_TOLERANCE_SECS {
        return Json(encrypt_response(&LoginResponseInner {
            status: "error".into(), session_token: None, message: Some("Invalid timestamp".into()), is_login: 0
        }));
    }

    // 2. 서명 검증
    let sign_str = format!("{}:{}", req.payload, req.timestamp);
    if !crypto::verify_signature(&sign_str, &req.signature, HMAC_SECRET) {
        return Json(encrypt_response(&LoginResponseInner {
            status: "error".into(), session_token: None, message: Some("Invalid signature".into()), is_login: 0
        }));
    }

    // 3. 복호화
    let decrypted = match crypto::decrypt(&req.payload, AES_KEY) {
        Ok(s) => s,
        Err(_) => return Json(encrypt_response(&LoginResponseInner {
            status: "error".into(), session_token: None, message: Some("Decryption failed".into()), is_login: 0
        })),
    };

    let inner: LoginRequestInner = serde_json::from_str(&decrypted).unwrap();
    
    // 4. DB 조회
    let res = sqlx::query("SELECT is_login FROM users WHERE user_id = ?")
        .bind(&inner.user_id)
        .fetch_optional(&state.db)
        .await;

    match res {
        Ok(Some(row)) => {
            let is_login: i8 = row.get("is_login");
            if is_login == 1 {
                let token = crypto::generate_session_token();
                state.sessions.lock().await.insert(inner.user_id.clone(), token.clone());
                Json(encrypt_response(&LoginResponseInner {
                    status: "ok".into(), session_token: Some(token), message: None, is_login: 1
                }))
            } else {
                Json(encrypt_response(&LoginResponseInner {
                    status: "error".into(), session_token: None, message: Some("매크로를 먼저 실행해주세요".into()), is_login: 0
                }))
            }
        }
        _ => Json(encrypt_response(&LoginResponseInner {
            status: "error".into(), session_token: None, message: Some("등록되지 않은 아이디입니다".into()), is_login: 0
        })),
    }
}

async fn heartbeat_handler(
    State(state): State<AppState>,
    Json(req): Json<EncryptedRequest>,
) -> Json<EncryptedResponse> {
    // 서명 및 복호화 (로그인과 동일하므로 생략하거나 공통화 가능, 여기선 핵심 로직만 기술)
    let decrypted = match crypto::decrypt(&req.payload, AES_KEY) {
        Ok(s) => s,
        Err(_) => return Json(encrypt_response(&HeartbeatResponseInner { status: "error".into(), action: None })),
    };

    let inner: HeartbeatRequestInner = serde_json::from_str(&decrypted).unwrap();
    
    // 세션 확인
    let sessions = state.sessions.lock().await;
    if sessions.contains_key(&inner.user_id) {
        Json(encrypt_response(&HeartbeatResponseInner { status: "ok".into(), action: None }))
    } else {
        Json(encrypt_response(&HeartbeatResponseInner { status: "error".into(), action: Some("kick".into()) }))
    }
}

#[tokio::main]
async fn main() {
    // CryptoProvider 설치 (Rustls 0.23 필수)
    rustls::crypto::ring::default_provider().install_default().ok();

    println!("🚀 LIE API Server starting (HTTPS Port 8084)...");

    // DB 연결
    let db_url = "mysql://user_account:Aa102331253910!@127.0.0.1:3306/maplestory_bot";
    let pool = MySqlPoolOptions::new()
        .max_connections(50)
        .connect(db_url)
        .await
        .expect("Failed to connect to User DB!");

    let state = AppState {
        db: pool,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    // TLS 설정
    let cert_path = "lie_cert.pem";
    let key_path = "lie_key.pem";
    if !std::path::Path::new(cert_path).exists() {
        let mut params = rcgen::CertificateParams::new(vec!["93.127.129.57".into(), "localhost".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 12, 31);
        let kp = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&kp).unwrap();
        std::fs::write(cert_path, cert.pem()).unwrap();
        std::fs::write(key_path, kp.serialize_pem()).unwrap();
    }

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await.unwrap();

    let app = Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/heartbeat", post(heartbeat_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8084));
    println!("✅ LIE HTTPS Server listening on https://{}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

mod ax_server { pub use axum_server::*; }
