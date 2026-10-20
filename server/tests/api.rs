//! Tests d'intégration de l'API (serveur réel sur un port local, PostgreSQL réel).
//!
//! Nécessitent une base PostgreSQL : définir `AUXIPAK_TEST_DATABASE_URL`
//! (connexion administrateur, ex. postgres://postgres:mdp@127.0.0.1:5432/postgres)
//! puis lancer `cargo test -p auxipak-server -- --include-ignored`.
//! Chaque test crée et supprime sa propre base.

use auxipak_server::{api, app, build_state, config::Config, initial_publish};
use reqwest::header::{HeaderMap, HeaderValue, COOKIE};
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;

struct Srv {
    base: String,
    http: reqwest::Client,
    admin_url: String,
    db: String,
    _dir: tempfile::TempDir,
    state: auxipak_server::state::AppState,
}

impl Drop for Srv {
    fn drop(&mut self) {
        let admin = self.admin_url.clone();
        let db = self.db.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                if let Ok(pool) = sqlx::PgPool::connect(&admin).await {
                    let _ = sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)")))
                        .execute(&pool)
                        .await;
                }
            });
        })
        .join()
        .ok();
    }
}

async fn start() -> Srv {
    let admin_url = std::env::var("AUXIPAK_TEST_DATABASE_URL").expect("AUXIPAK_TEST_DATABASE_URL requis");
    let db = format!("auxipak_t_{}", uuid::Uuid::new_v4().simple());
    let pool = sqlx::PgPool::connect(&admin_url).await.unwrap();
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {db}")))
        .execute(&pool)
        .await
        .unwrap();
    let db_url = format!("{}/{db}", admin_url.rsplit_once('/').unwrap().0);
    let dir = tempfile::tempdir().unwrap();
    let cfg = Config::for_tests(&db_url, dir.path().join("data"), dir.path().join("keys"));
    let state = build_state(cfg).await.unwrap();
    initial_publish(&state).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let svc = app(state.clone()).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, svc).await.unwrap() });
    Srv {
        base: format!("http://{addr}"),
        http: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
        admin_url,
        db,
        _dir: dir,
        state,
    }
}

/// Session Web/API (cookie + jeton CSRF).
struct Session {
    cookie: String,
    csrf: String,
}

impl Srv {
    fn url(&self, p: &str) -> String {
        format!("{}{p}", self.base)
    }

    async fn user(&self, name: &str, role: auxipak_server::auth::Role) -> String {
        let pw = format!("Mot-de-passe-{name}-2026");
        api::admin::insert_user(&self.state, name, name, &pw, role).await.unwrap();
        pw
    }

    async fn login(&self, name: &str, pw: &str) -> Session {
        let r = self
            .http
            .post(self.url("/api/v1/auth/login"))
            .json(&json!({"username": name, "password": pw}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let cookie = r
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
            .find(|c| c.starts_with("auxipak_session="))
            .unwrap();
        let body: Value = r.json().await.unwrap();
        Session {
            cookie,
            csrf: body["csrf_token"].as_str().unwrap().to_string(),
        }
    }

    fn sh(&self, s: &Session) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, HeaderValue::from_str(&s.cookie).unwrap());
        h.insert("x-csrf-token", HeaderValue::from_str(&s.csrf).unwrap());
        h
    }

    async fn token(&self, admin: &Session, user: &str, kind: &str, scopes: &[&str]) -> String {
        let users: Value = self
            .http
            .get(self.url("/api/v1/admin/users"))
            .headers(self.sh(admin))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = users.as_array().unwrap().iter().find(|u| u["username"] == user).unwrap()["id"].clone();
        let r = self
            .http
            .post(self.url("/api/v1/admin/tokens"))
            .headers(self.sh(admin))
            .json(&json!({"name": format!("{kind} test"), "kind": kind, "scopes": scopes, "user_id": id, "provider": "test"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
        r.json::<Value>().await.unwrap()["token"].as_str().unwrap().to_string()
    }

    async fn submit(&self, token: &str, bytes: Vec<u8>) -> Value {
        let r = self
            .http
            .post(self.url("/api/v1/submissions?repository=official&file_name=Demo-1.0.0-fr.aupak"))
            .bearer_auth(token)
            .body(bytes)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
        r.json().await.unwrap()
    }
}

fn demo_aupak(version: &str) -> Vec<u8> {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("payload/bin")).unwrap();
    std::fs::write(
        d.path().join("instruction.auxipak"),
        auxipak_core::project::render_template("demo-app", "Demo App", version, "AuxiNux", "fr", "MIT"),
    )
    .unwrap();
    std::fs::write(d.path().join("payload/bin/demo-app"), b"#!/bin/sh\necho demo\n").unwrap();
    let out: PathBuf = d.path().join("x.aupak");
    auxipak_core::project::build(d.path(), &out).unwrap();
    std::fs::read(out).unwrap()
}

use auxipak_server::auth::Role;

#[tokio::test]
#[ignore = "requiert PostgreSQL (AUXIPAK_TEST_DATABASE_URL)"]
async fn public_endpoints_and_openapi_completeness() {
    let s = start().await;
    let h: Value = s
        .http
        .get(s.url("/api/v1/health"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(h["status"], "ok");
    let idx: Value = s.http.get(s.url("/index")).send().await.unwrap().json().await.unwrap();
    assert_eq!(idx["repositories"][0]["name"], "official");
    assert_eq!(idx["repositories"][0]["official"], true);
    let r = s
        .http
        .get(s.url("/repos/official/metadata/timestamp.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        s.http
            .get(s.url("/repos/official/metadata/1.root.json"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        s.http
            .get(s.url("/repos/official/keys/package-keys.json"))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    // Traversée de répertoires et fichiers hors du dépôt publié.
    for bad in [
        "/repos/official/../../etc/passwd",
        "/repos/official/metadata/..%2f..%2fkeys",
        "/repos/official/other/x",
        "/repos/..%2f/x",
    ] {
        let st = s.http.get(s.url(bad)).send().await.unwrap().status();
        assert!(st == StatusCode::NOT_FOUND || st == StatusCode::BAD_REQUEST, "{bad} → {st}");
    }
    // Chaque route est documentée dans openapi.yaml.
    let spec: Value = serde_yaml_ng::from_str(api::public::OPENAPI).unwrap();
    for (method, path) in api::DOCUMENTED_ROUTES {
        assert!(
            spec["paths"][path][method].is_object(),
            "route non documentée : {method} {path}"
        );
    }
    let html = s.http.get(s.url("/")).send().await.unwrap().text().await.unwrap();
    assert!(html.contains("<html lang=\"fr\">") && html.contains("Catalogue"));
    let r = s.http.get(s.url("/lang/en")).send().await.unwrap();
    let cookie = r
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let html = s
        .http
        .get(s.url("/values"))
        .header(COOKIE, cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("<html lang=\"en\">") && html.contains("AuxiNux values"));
    let r = s.http.get(s.url("/lang/fr?next=//evil.example")).send().await.unwrap();
    assert_eq!(r.headers().get("location").unwrap(), "/", "pas de redirection ouverte");
}

#[tokio::test]
#[ignore = "requiert PostgreSQL (AUXIPAK_TEST_DATABASE_URL)"]
async fn authentication_csrf_and_throttling() {
    let s = start().await;
    let pw = s.user("alice", Role::Admin).await;
    let r = s
        .http
        .post(s.url("/api/v1/auth/login"))
        .json(&json!({"username": "alice", "password": "faux-mot-de-passe"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let sess = s.login("alice", &pw).await;
    // Requête non sûre avec session mais sans jeton CSRF : refusée.
    let r = s
        .http
        .post(s.url("/api/v1/admin/repositories"))
        .header(COOKIE, &sess.cookie)
        .json(&json!({"name": "x", "title": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Anonyme : 401 sur toute l'administration.
    for p in [
        "/api/v1/admin/users",
        "/api/v1/admin/audit",
        "/api/v1/submissions",
        "/api/v1/builder/projects",
    ] {
        assert_eq!(
            s.http.get(s.url(p)).send().await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "{p}"
        );
    }
    assert_eq!(
        s.http
            .get(s.url("/api/v1/auth/me"))
            .bearer_auth("apk_inconnu")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Limitation des tentatives.
    let mut last = StatusCode::OK;
    for _ in 0..7 {
        last = s
            .http
            .post(s.url("/api/v1/auth/login"))
            .json(&json!({"username": "bob", "password": "x"}))
            .send()
            .await
            .unwrap()
            .status();
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
    // Déconnexion : la session n'est plus valable.
    s.http
        .post(s.url("/api/v1/auth/logout"))
        .headers(s.sh(&sess))
        .send()
        .await
        .unwrap();
    assert_eq!(
        s.http
            .get(s.url("/api/v1/auth/me"))
            .header(COOKIE, &sess.cookie)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Mot de passe faible refusé.
    let sess = s.login("alice", &pw).await;
    let r = s
        .http
        .post(s.url("/api/v1/admin/users"))
        .headers(s.sh(&sess))
        .json(&json!({"username": "weak", "password": "court", "role": "publisher"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
#[ignore = "requiert PostgreSQL (AUXIPAK_TEST_DATABASE_URL)"]
async fn publication_policy_classification_and_revocation() {
    let s = start().await;
    let admin_pw = s.user("admin", Role::Admin).await;
    s.user("pub", Role::Publisher).await;
    s.user("rev", Role::Reviewer).await;
    let admin = s.login("admin", &admin_pw).await;
    let pub_token = s.token(&admin, "pub", "human", &["submit", "read"]).await;
    let agent = s.token(&admin, "rev", "agent", &["build", "submit"]).await;
    let ci = s.token(&admin, "rev", "ci", &["submit"]).await;
    // Les jetons agent/ci ne peuvent jamais recevoir de portée sensible.
    for (kind, scope) in [
        ("agent", "review"),
        ("agent", "evaluate"),
        ("ci", "admin"),
        ("agent", "admin"),
    ] {
        let users: Value = s
            .http
            .get(s.url("/api/v1/admin/users"))
            .headers(s.sh(&admin))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let id = users.as_array().unwrap().iter().find(|u| u["username"] == "rev").unwrap()["id"].clone();
        let r = s
            .http
            .post(s.url("/api/v1/admin/tokens"))
            .headers(s.sh(&admin))
            .json(&json!({"name": "x", "kind": kind, "scopes": [scope], "user_id": id}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{kind}/{scope}");
    }
    // Un publieur ne peut pas obtenir la portée review (rôle insuffisant).
    let r = s
        .http
        .post(s.url("/api/v1/tokens"))
        .bearer_auth(&pub_token)
        .json(&json!({"name": "x", "kind": "human", "scopes": ["submit"]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN, "un jeton ne peut pas créer de jeton");

    // Soumission invalide.
    let bad = s.submit(&pub_token, b"pas une archive".to_vec()).await;
    assert_eq!(bad["status"], "invalid");
    // Soumission valide par le publieur.
    let sub = s.submit(&pub_token, demo_aupak("1.0.0")).await;
    assert_eq!(sub["status"], "pending");
    assert_eq!(sub["submitter_kind"], "human");
    let id = sub["id"].as_str().unwrap();
    // Personne ne publie sans la portée review ; un agent ou un jeton CI non plus.
    for t in [&pub_token, &agent, &ci] {
        let r = s
            .http
            .post(s.url(&format!("/api/v1/submissions/{id}/approve")))
            .bearer_auth(t)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }
    // L'auteur ne peut pas approuver sa propre demande (politique des quatre yeux).
    let pub_session_pw = "Mot-de-passe-pub-2026";
    let pub_sess = s.login("pub", pub_session_pw).await;
    let r = s
        .http
        .post(s.url(&format!("/api/v1/submissions/{id}/approve")))
        .headers(s.sh(&pub_sess))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Le relecteur approuve.
    let rev = s.login("rev", "Mot-de-passe-rev-2026").await;
    let r = s
        .http
        .post(s.url(&format!("/api/v1/submissions/{id}/approve")))
        .headers(s.sh(&rev))
        .json(&json!({"note": "ok"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "{}", r.text().await.unwrap());
    // Une demande traitée ne peut plus être approuvée ; une soumission invalide non plus.
    let r = s
        .http
        .post(s.url(&format!("/api/v1/submissions/{id}/approve")))
        .headers(s.sh(&rev))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let bid = bad["id"].as_str().unwrap();
    assert_eq!(
        s.http
            .post(s.url(&format!("/api/v1/submissions/{bid}/approve")))
            .headers(s.sh(&rev))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    // Republier la même version : conflit.
    let dup = s.submit(&pub_token, demo_aupak("1.0.0")).await;
    let r = s
        .http
        .post(s.url(&format!("/api/v1/submissions/{}/approve", dup["id"].as_str().unwrap())))
        .headers(s.sh(&rev))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);

    // Index et paquet publiés, signés, téléchargeables avec reprise.
    let apps: Value = s
        .http
        .get(s.url("/repos/official/targets/apps.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(apps["apps"][0]["id"], "demo-app");
    assert_eq!(
        apps["apps"][0]["status"], "unreviewed",
        "une nouvelle application n'est jamais classée d'office"
    );
    let ch: Value = s
        .http
        .get(s.url("/repos/official/targets/channels/linux/deb/x86_64.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rel = &ch["releases"][0];
    let pkg = s
        .http
        .get(s.url(&format!("/repos/official/targets/{}", rel["target"].as_str().unwrap())))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(auxipak_core::hash::sha256_hex(&pkg), rel["sha256"].as_str().unwrap());
    let part = s
        .http
        .get(s.url(&format!("/repos/official/targets/{}", rel["target"].as_str().unwrap())))
        .header("range", "bytes=10-")
        .send()
        .await
        .unwrap();
    assert_eq!(part.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(part.bytes().await.unwrap().as_ref(), &pkg[10..]);
    let sig: auxipak_core::signature::PackageSignature = s
        .http
        .get(s.url(&format!(
            "/repos/official/targets/{}",
            rel["signature"]["target"].as_str().unwrap()
        )))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    sig.verify(
        rel["sha256"].as_str().unwrap(),
        pkg.len() as u64,
        &s.state.keys.package_keys,
        &[auxipak_core::signature::KeyPurpose::PackageSigning],
    )
    .unwrap();

    // Classification : humain uniquement, réserves obligatoires pour « compatible ».
    let r = s
        .http
        .put(s.url("/api/v1/admin/apps/demo-app/evaluation"))
        .bearer_auth(&agent)
        .json(&json!({"status": "verified"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = s
        .http
        .put(s.url("/api/v1/admin/apps/demo-app/evaluation"))
        .headers(s.sh(&rev))
        .json(&json!({"status": "compatible"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let r = s
        .http
        .put(s.url("/api/v1/admin/apps/demo-app/evaluation"))
        .headers(s.sh(&rev))
        .json(&json!({"status": "verified", "note": "conforme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let apps: Value = s
        .http
        .get(s.url("/repos/official/targets/apps.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(apps["apps"][0]["status"], "verified");

    // Révocation : motif obligatoire, définitive, publiée dans revocations.json.
    let rels: Value = s
        .http
        .get(s.url("/api/v1/admin/releases?app_id=demo-app"))
        .headers(s.sh(&rev))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rid = rels[0]["id"].as_str().unwrap();
    let st = |state: &'static str, reason: &'static str| {
        s.http
            .post(s.url(&format!("/api/v1/admin/releases/{rid}/state")))
            .headers(s.sh(&rev))
            .json(&json!({"state": state, "reason": reason}))
            .send()
    };
    assert_eq!(st("revoked", "").await.unwrap().status(), StatusCode::BAD_REQUEST);
    assert_eq!(st("revoked", "compromis").await.unwrap().status(), StatusCode::OK);
    assert_eq!(st("published", "").await.unwrap().status(), StatusCode::CONFLICT);
    let revs: Value = s
        .http
        .get(s.url("/repos/official/targets/revocations.json"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(revs["revoked"][0]["id"], "demo-app");
    let ch = s
        .http
        .get(s.url("/repos/official/targets/channels/linux/deb/x86_64.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        ch.status(),
        StatusCode::NOT_FOUND,
        "plus aucune version publiée dans ce canal"
    );

    // Journal d'audit : réservé aux administrateurs, contient les actions.
    assert_eq!(
        s.http
            .get(s.url("/api/v1/admin/audit"))
            .headers(s.sh(&rev))
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let audit: Value = s
        .http
        .get(s.url("/api/v1/admin/audit"))
        .headers(s.sh(&admin))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    for a in [
        "submission.create",
        "submission.approve",
        "app.evaluate",
        "release.revoked",
        "token.create",
    ] {
        assert!(actions.contains(&a), "{a} absent du journal");
    }
}

#[tokio::test]
#[ignore = "requiert PostgreSQL (AUXIPAK_TEST_DATABASE_URL)"]
async fn builder_api_flow_with_agent_token() {
    let s = start().await;
    let admin_pw = s.user("admin", Role::Admin).await;
    s.user("bot-owner", Role::Publisher).await;
    let admin = s.login("admin", &admin_pw).await;
    let agent = s.token(&admin, "bot-owner", "agent", &["build", "submit"]).await;
    let r = s
        .http
        .post(s.url("/api/v1/builder/projects"))
        .bearer_auth(&agent)
        .json(&json!({"name": "Mon app", "id": "mon-app", "version": "0.1.0"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let p: Value = r.json().await.unwrap();
    let id = p["id"].as_str().unwrap();
    // Fichiers : chemins dangereux refusés.
    for bad in ["payload/..%2F..%2Fescape", "autre/x", "scripts/..%2Fx"] {
        let st = s
            .http
            .put(s.url(&format!("/api/v1/builder/projects/{id}/files/{bad}")))
            .bearer_auth(&agent)
            .body("x")
            .send()
            .await
            .unwrap()
            .status();
        assert!(st == StatusCode::BAD_REQUEST || st == StatusCode::NOT_FOUND, "{bad} → {st}");
    }
    let r = s
        .http
        .put(s.url(&format!("/api/v1/builder/projects/{id}/files/payload/bin/mon-app")))
        .bearer_auth(&agent)
        .body("#!/bin/sh\necho salut\n")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // Métadonnées et plateformes par fusion JSON.
    let r = s
        .http
        .patch(s.url(&format!("/api/v1/builder/projects/{id}/manifest")))
        .bearer_auth(&agent)
        .json(&json!({"summary": "Application générée par un agent", "publisher": "Bot", "dependencies": [{"id": "autre-app", "version": ">=1"}]}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v: Value = s
        .http
        .post(s.url(&format!("/api/v1/builder/projects/{id}/validate")))
        .bearer_auth(&agent)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["valid"], true, "{v}");
    let b: Value = s
        .http
        .post(s.url(&format!("/api/v1/builder/projects/{id}/build")))
        .bearer_auth(&agent)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(b["ok"], true, "{b}");
    let t: Value = s
        .http
        .post(s.url(&format!("/api/v1/builder/projects/{id}/test")))
        .bearer_auth(&agent)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(t["ok"], true, "{t}");
    let art = s
        .http
        .get(s.url(&format!("/api/v1/builder/projects/{id}/artifact")))
        .bearer_auth(&agent)
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(auxipak_core::hash::sha256_hex(&art), b["sha256"].as_str().unwrap());
    let sub: Value = s
        .http
        .post(s.url(&format!("/api/v1/builder/projects/{id}/submit")))
        .bearer_auth(&agent)
        .json(&json!({"note": "agent"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(sub["status"], "pending");
    assert_eq!(sub["submitter_kind"], "agent");
    // L'agent ne peut toujours pas publier.
    let r = s
        .http
        .post(s.url(&format!("/api/v1/submissions/{}/approve", sub["id"].as_str().unwrap())))
        .bearer_auth(&agent)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    // Un projet n'est visible que par son propriétaire.
    s.user("other", Role::Publisher).await;
    let other = s.token(&admin, "other", "human", &["build"]).await;
    assert_eq!(
        s.http
            .get(s.url(&format!("/api/v1/builder/projects/{id}")))
            .bearer_auth(&other)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    // Manifeste invalide : la validation l'indique.
    s.http
        .put(s.url(&format!("/api/v1/builder/projects/{id}/manifest")))
        .bearer_auth(&agent)
        .body("format: 1\nid: MAUVAIS\n")
        .send()
        .await
        .unwrap();
    let v: Value = s
        .http
        .post(s.url(&format!("/api/v1/builder/projects/{id}/validate")))
        .bearer_auth(&agent)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["valid"], false);
}

#[tokio::test]
#[ignore = "requiert PostgreSQL (AUXIPAK_TEST_DATABASE_URL)"]
async fn web_admin_requires_session_and_csrf() {
    let s = start().await;
    let pw = s.user("admin", Role::Admin).await;
    let r = s.http.get(s.url("/admin")).send().await.unwrap();
    assert!(r.status().is_redirection());
    let r = s
        .http
        .post(s.url("/admin/login"))
        .form(&[("username", "admin"), ("password", pw.as_str())])
        .send()
        .await
        .unwrap();
    assert!(r.status().is_redirection());
    let cookie = r
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(r.headers().get("set-cookie").unwrap().to_str().unwrap().contains("HttpOnly"));
    let html = s
        .http
        .get(s.url("/admin"))
        .header(COOKIE, &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(html.contains("Tableau de bord"));
    for page in [
        "/admin/submissions",
        "/admin/upload",
        "/admin/releases",
        "/admin/apps",
        "/admin/repositories",
        "/admin/users",
        "/admin/tokens",
        "/admin/audit",
    ] {
        let r = s.http.get(s.url(page)).header(COOKIE, &cookie).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{page}");
    }
    // Formulaire sans jeton CSRF valide : refusé.
    let r = s
        .http
        .post(s.url("/admin/users"))
        .header(COOKIE, &cookie)
        .form(&[
            ("csrf", "faux"),
            ("username", "x1"),
            ("password", "Un-mot-de-passe-long"),
            ("role", "admin"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    assert!(api::admin::users(&s.state).await.unwrap().iter().all(|u| u.username != "x1"));
    // En-têtes de sécurité.
    let r = s.http.get(s.url("/")).send().await.unwrap();
    assert!(r
        .headers()
        .get("content-security-policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("default-src 'self'"));
    assert_eq!(r.headers().get("x-frame-options").unwrap(), "DENY");
}

#[tokio::test]
#[ignore = "requiert PostgreSQL (AUXIPAK_TEST_DATABASE_URL)"]
async fn install_scripts_and_downloads() {
    let s = start().await;
    let root = String::from_utf8(s.state.keys.root_json.clone()).unwrap();
    for (p, needle) in [
        ("/install.sh", root.trim()),
        ("/uninstall.sh", "--purge"),
        ("/install.ps1", "FromBase64String"),
        ("/uninstall.ps1", "AUXIPAK_PURGE"),
    ] {
        let r = s.http.get(s.url(p)).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "{p}");
        assert!(r.headers()["content-type"].to_str().unwrap().starts_with("text/plain"));
        let body = r.text().await.unwrap();
        assert!(!body.contains("@@"), "{p} : gabarit incomplet");
        assert!(body.contains("http://127.0.0.1"), "{p} : URL publique absente");
        assert!(body.contains(needle), "{p}");
    }
    // Aucun client publié : 404 ; fichiers hors liste et traversée refusés.
    assert_eq!(
        s.http.get(s.url("/downloads/SHA256SUMS")).send().await.unwrap().status(),
        StatusCode::NOT_FOUND
    );
    let dl = &s.state.config.downloads_dir;
    std::fs::create_dir_all(dl).unwrap();
    std::fs::write(dl.join("SHA256SUMS"), "x").unwrap();
    std::fs::write(dl.join(".secret"), "x").unwrap();
    assert_eq!(
        s.http
            .get(s.url("/downloads/SHA256SUMS"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "x"
    );
    for p in [
        "/downloads/.secret",
        "/downloads/..%2F..%2Fkeys%2Froot.json",
        "/downloads/a%20b",
    ] {
        assert_eq!(
            s.http.get(s.url(p)).send().await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "{p}"
        );
    }
}
