use axum::{
    extract::{Json, State},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    db: MySqlPool,
}

#[derive(Deserialize)]
struct LoginRequest {
    user_id: String,
    #[allow(dead_code)]
    program: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    status: String,
    message: Option<String>,
}

#[derive(Deserialize)]
struct HeartbeatRequest {
    user_id: String,
    #[allow(dead_code)]
    program: Option<String>,
}

#[derive(Serialize)]
struct HeartbeatResponse {
    status: String,
    action: Option<String>,
}

async fn login_handler(
    State(state): State<AppState>,
    Json(payload): Json<LoginRequest>,
) -> Json<LoginResponse> {
    let res = sqlx::query("SELECT is_login FROM users WHERE user_id = ?")
        .bind(&payload.user_id)
        .fetch_optional(&state.db)
        .await;

    match res {
        Ok(Some(row)) => {
            let is_login: i8 = row.get("is_login");
            if is_login == 1 {
                Json(LoginResponse { status: "ok".into(), message: None })
            } else {
                Json(LoginResponse { status: "error".into(), message: Some("매크로를 먼저 실행해주세요".into()) })
            }
        }
        _ => Json(LoginResponse { status: "error".into(), message: Some("등록되지 않은 아이디입니다".into()) }),
    }
}

async fn heartbeat_handler(
    State(state): State<AppState>,
    Json(payload): Json<HeartbeatRequest>,
) -> Json<HeartbeatResponse> {
    let res = sqlx::query("SELECT is_login FROM users WHERE user_id = ?")
        .bind(&payload.user_id)
        .fetch_optional(&state.db)
        .await;

    match res {
        Ok(Some(row)) => {
            let is_login: i8 = row.get("is_login");
            if is_login == 1 {
                Json(HeartbeatResponse { status: "ok".into(), action: None })
            } else {
                Json(HeartbeatResponse { status: "error".into(), action: Some("kick".into()) })
            }
        }
        _ => Json(HeartbeatResponse { status: "error".into(), action: Some("kick".into()) }),
    }
}

#[tokio::main]
async fn main() {
    println!("🚀 Simple LIE API Server starting (HTTP Port 8084)...");

    let db_url = "mysql://user_account:Aa102331253910!@127.0.0.1:3306/maplestory_bot";
    let pool = MySqlPoolOptions::new()
        .max_connections(50)
        .connect(db_url)
        .await
        .expect("Failed to connect to User DB!");

    let state = AppState { db: pool };

    let app = Router::new()
        .route("/api/login", post(login_handler))
        .route("/api/heartbeat", post(heartbeat_handler))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8084));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("✅ Server is running on http://{}", addr);

    axum::serve(listener, app).await.unwrap();
}
