//! Journal d'audit (traçabilité des opérations sensibles).

use crate::auth::Actor;
use sqlx::PgPool;

pub async fn log(db: &PgPool, actor: Option<&Actor>, action: &str, target: &str, details: serde_json::Value) {
    let (uid, name, kind, ip) = match actor {
        Some(a) => (Some(a.user_id), a.display(), a.kind().to_string(), a.ip.clone()),
        None => (None, "system".to_string(), "system".to_string(), None),
    };
    tracing::info!(actor = %name, action, target, "audit");
    let r = sqlx::query(
        "INSERT INTO audit_log (actor_user, actor_name, actor_kind, action, target, details, ip) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(uid)
    .bind(name)
    .bind(kind)
    .bind(action)
    .bind(target)
    .bind(details)
    .bind(ip)
    .execute(db)
    .await;
    if let Err(e) = r {
        tracing::error!(error = %e, "{}", auxipak_core::tr!("écriture du journal d'audit impossible", "cannot write the audit log"));
    }
}
