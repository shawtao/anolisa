//! Serve subcommand — start the API server

use agentsight::server::run_server;
use agentsight::storage::sqlite::GenAISqliteStore;
use structopt::StructOpt;

/// Start the AgentSight API server
#[derive(Debug, StructOpt, Clone)]
pub struct ServeCommand {
    /// Host to bind to
    #[structopt(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Port to bind to
    #[structopt(long, default_value = "7396")]
    pub port: u16,

    /// Custom database path
    #[structopt(long)]
    pub db: Option<String>,

    /// Custom raw_events.db path (defaults to <genai_db_dir>/raw_events.db)
    #[structopt(long)]
    pub raw_events_db: Option<String>,
}

impl ServeCommand {
    pub fn execute(&self) {
        let db_path = self.db
            .as_ref()
            .map(|p| std::path::PathBuf::from(p))
            // Default to genai_events.db — the same file the tracer writes to
            .unwrap_or_else(|| GenAISqliteStore::default_path());

        // Default raw_events.db to a sibling of the genai db.
        let raw_events_db_path = self
            .raw_events_db
            .as_ref()
            .map(|p| std::path::PathBuf::from(p))
            .or_else(|| {
                db_path
                    .parent()
                    .map(|p| p.join("raw_events.db"))
            });

        let host = self.host.clone();
        let port = self.port;

        actix_web::rt::System::new().block_on(async move {
            if let Err(e) = run_server(&host, port, db_path, raw_events_db_path).await {
                eprintln!("Server error: {}", e);
                std::process::exit(1);
            }
        });
    }
}
