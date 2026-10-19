//! État partagé du serveur.

use crate::auth::LoginThrottle;
use crate::config::Config;
use crate::keys::Keys;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: PgPool,
    pub keys: Arc<Keys>,
    pub throttle: Arc<LoginThrottle>,
    /// Sérialise la régénération des dépôts dans ce processus (un verrou
    /// consultatif PostgreSQL protège aussi contre plusieurs instances).
    pub publish_lock: Arc<tokio::sync::Mutex<()>>,
    pub web: Arc<crate::web::Templates>,
}
