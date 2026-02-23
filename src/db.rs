use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension};
use tracing::{debug, info};

use crate::github::GitHubTriggerConfig;
use crate::jira::JiraTriggerConfig;
use crate::slack::SlackTriggerConfig;

/// Lightweight SQLite-backed store for webhook secrets and trigger metadata.
///
/// **Webhook secrets** are captured in real-time by the provider mock endpoints
/// (e.g. `POST /provider/github/repos/:owner/:repo/hooks`) and stored here so
/// they are immediately available for payload re-signing -- no need to wait for
/// n8n's `staticData` to be populated.
///
/// **Trigger metadata** is written by the periodic sync job (same data that was
/// previously kept in `Arc<RwLock<Vec<TriggerConfig>>>`).
pub struct Database {
    conn: Mutex<Connection>,
}

// ── Row types returned by query methods ─────────────────────────────────────

/// A GitHub trigger row joined with its optional webhook secret.
pub struct GitHubTriggerRow {
    pub webhook_id: String,
    pub workflow_name: String,
    pub workflow_active: bool,
    pub events: Vec<String>,
    /// HMAC secret from `webhook_secrets` (if captured by provider mock or staticData fallback).
    pub secret: Option<String>,
}

/// A Jira trigger row from the database.
pub struct JiraTriggerRow {
    pub webhook_id: String,
    pub workflow_name: String,
    pub workflow_active: bool,
    pub events: Vec<String>,
}

/// A Slack trigger row from the database.
pub struct SlackTriggerRow {
    pub webhook_id: String,
    pub workflow_name: String,
    pub workflow_active: bool,
    pub event_type: String,
    pub channels: Vec<String>,
    pub watch_whole_workspace: bool,
}

impl Database {
    /// Open (or create) the database at `path` and run migrations.
    /// Use `":memory:"` for an in-memory database (useful for tests).
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        let db = Self {
            conn: Mutex::new(conn),
        };
        db.create_schema()?;
        info!(path = %path, "Database opened and schema verified");
        Ok(db)
    }

    fn create_schema(&self) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock();
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS webhook_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                webhook_id TEXT NOT NULL UNIQUE,
                provider TEXT NOT NULL,
                secret TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS github_triggers (
                webhook_id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                workflow_active BOOLEAN NOT NULL DEFAULT 0,
                owner TEXT NOT NULL DEFAULT '',
                repository TEXT NOT NULL DEFAULT '',
                events TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS jira_triggers (
                webhook_id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                workflow_active BOOLEAN NOT NULL DEFAULT 0,
                events TEXT NOT NULL DEFAULT '[]',
                updated_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS slack_triggers (
                webhook_id TEXT PRIMARY KEY,
                workflow_id TEXT NOT NULL,
                workflow_name TEXT NOT NULL,
                workflow_active BOOLEAN NOT NULL DEFAULT 0,
                event_type TEXT NOT NULL DEFAULT '',
                channels TEXT NOT NULL DEFAULT '[]',
                watch_whole_workspace BOOLEAN NOT NULL DEFAULT 0,
                updated_at TEXT DEFAULT (datetime('now'))
            );
            ",
        )?;
        Ok(())
    }

    // ── Webhook secrets ─────────────────────────────────────────────────

    /// Insert or update a webhook secret captured by a provider mock endpoint.
    ///
    /// Returns the numeric row ID (used as the external "hook id" in mock API
    /// responses so n8n can reference it during DELETE).
    pub fn upsert_webhook_secret(
        &self,
        webhook_id: &str,
        provider: &str,
        secret: &str,
    ) -> Result<i64, rusqlite::Error> {
        let conn = self.conn.lock();

        // Check for an existing row so we can preserve its stable numeric id
        let existing_id: Option<i64> = conn
            .query_row(
                "SELECT id FROM webhook_secrets WHERE webhook_id = ?1",
                rusqlite::params![webhook_id],
                |row| row.get(0),
            )
            .optional()?;

        match existing_id {
            Some(id) => {
                conn.execute(
                    "UPDATE webhook_secrets SET secret = ?1, provider = ?2 WHERE id = ?3",
                    rusqlite::params![secret, provider, id],
                )?;
                debug!(webhook_id = %webhook_id, hook_id = id, "Updated existing webhook secret");
                Ok(id)
            }
            None => {
                conn.execute(
                    "INSERT INTO webhook_secrets (webhook_id, provider, secret) VALUES (?1, ?2, ?3)",
                    rusqlite::params![webhook_id, provider, secret],
                )?;
                let id = conn.last_insert_rowid();
                debug!(webhook_id = %webhook_id, hook_id = id, "Inserted new webhook secret");
                Ok(id)
            }
        }
    }

    /// Insert a webhook secret only if one doesn't already exist for this
    /// `webhook_id`. Used by the trigger sync to persist `staticData` secrets
    /// as a fallback without overwriting provider-captured secrets.
    pub fn upsert_webhook_secret_fallback(
        &self,
        webhook_id: &str,
        provider: &str,
        secret: &str,
    ) -> Result<(), rusqlite::Error> {
        let conn = self.conn.lock();
        conn.execute(
            "INSERT OR IGNORE INTO webhook_secrets (webhook_id, provider, secret) VALUES (?1, ?2, ?3)",
            rusqlite::params![webhook_id, provider, secret],
        )?;
        Ok(())
    }

    /// Delete a webhook secret by its numeric row ID (the "hook id" from mock
    /// API responses).
    pub fn delete_webhook_secret_by_id(&self, id: i64) -> Result<bool, rusqlite::Error> {
        let conn = self.conn.lock();
        let deleted = conn.execute(
            "DELETE FROM webhook_secrets WHERE id = ?1",
            rusqlite::params![id],
        )?;
        Ok(deleted > 0)
    }

    /// Retrieve the secret stored for a given `webhook_id`, if any.
    ///
    /// Returns `Ok(Some(secret))` if found, `Ok(None)` if no row exists for
    /// this webhook ID.  Currently used only in tests; the production hot-path
    /// obtains secrets through the `query_github_triggers` JOIN.
    #[cfg(test)]
    pub fn get_webhook_secret(&self, webhook_id: &str) -> Result<Option<String>, rusqlite::Error> {
        let conn = self.conn.lock();
        conn.query_row(
            "SELECT secret FROM webhook_secrets WHERE webhook_id = ?1",
            rusqlite::params![webhook_id],
            |row| row.get(0),
        )
        .optional()
    }

    // ── GitHub triggers ─────────────────────────────────────────────────

    /// Replace all GitHub trigger rows with the supplied set (inside a
    /// transaction). This is called by the periodic sync job.
    pub fn sync_github_triggers(
        &self,
        triggers: &[GitHubTriggerConfig],
    ) -> Result<(), rusqlite::Error> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM github_triggers", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO github_triggers \
                 (webhook_id, workflow_id, workflow_name, workflow_active, owner, repository, events) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for t in triggers {
                let events_json =
                    serde_json::to_string(&t.events).unwrap_or_else(|_| "[]".to_string());
                stmt.execute(rusqlite::params![
                    t.webhook_id,
                    t.workflow_id,
                    t.workflow_name,
                    t.workflow_active,
                    t.owner,
                    t.repository,
                    events_json,
                ])?;
            }
        }
        tx.commit()?;
        debug!(count = triggers.len(), "Synced GitHub triggers to database");
        Ok(())
    }

    /// Query GitHub triggers matching the given owner/repository, joined with
    /// `webhook_secrets` to include the HMAC secret (if available).
    ///
    /// When `owner` and `repository` are both `Some`, the query filters by
    /// case-insensitive match. When either is `None`, only triggers with empty
    /// owner/repository are returned (for rare org-level events).
    pub fn query_github_triggers(
        &self,
        owner: Option<&str>,
        repository: Option<&str>,
    ) -> Result<Vec<GitHubTriggerRow>, rusqlite::Error> {
        let conn = self.conn.lock();

        let base_sql = "\
            SELECT gt.webhook_id, gt.workflow_name, gt.workflow_active, \
                   gt.events, ws.secret \
            FROM github_triggers gt \
            LEFT JOIN webhook_secrets ws ON gt.webhook_id = ws.webhook_id";

        match (owner, repository) {
            (Some(o), Some(r)) => {
                let sql = format!(
                    "{base_sql} WHERE LOWER(gt.owner) = LOWER(?1) AND LOWER(gt.repository) = LOWER(?2)"
                );
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt
                    .query_map(rusqlite::params![o, r], Self::map_github_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            }
            _ => {
                let sql = format!("{base_sql} WHERE gt.owner = '' AND gt.repository = ''");
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt
                    .query_map([], Self::map_github_row)?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            }
        }
    }

    fn map_github_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GitHubTriggerRow> {
        let events_json: String = row.get(3)?;
        let events: Vec<String> = serde_json::from_str(&events_json).unwrap_or_default();
        Ok(GitHubTriggerRow {
            webhook_id: row.get(0)?,
            workflow_name: row.get(1)?,
            workflow_active: row.get(2)?,
            events,
            secret: row.get(4)?,
        })
    }

    /// Count the total number of GitHub trigger rows (for health checks).
    pub fn count_github_triggers(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM github_triggers", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    // ── Jira triggers ───────────────────────────────────────────────────

    /// Replace all Jira trigger rows with the supplied set.
    pub fn sync_jira_triggers(
        &self,
        triggers: &[JiraTriggerConfig],
    ) -> Result<(), rusqlite::Error> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM jira_triggers", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO jira_triggers \
                 (webhook_id, workflow_id, workflow_name, workflow_active, events) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
            )?;
            for t in triggers {
                let events_json =
                    serde_json::to_string(&t.events).unwrap_or_else(|_| "[]".to_string());
                stmt.execute(rusqlite::params![
                    t.webhook_id,
                    t.workflow_id,
                    t.workflow_name,
                    t.workflow_active,
                    events_json,
                ])?;
            }
        }
        tx.commit()?;
        debug!(count = triggers.len(), "Synced Jira triggers to database");
        Ok(())
    }

    /// Query all Jira triggers.
    pub fn query_jira_triggers(&self) -> Result<Vec<JiraTriggerRow>, rusqlite::Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT webhook_id, workflow_name, workflow_active, events \
             FROM jira_triggers",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let events_json: String = row.get(3)?;
                let events: Vec<String> = serde_json::from_str(&events_json).unwrap_or_default();
                Ok(JiraTriggerRow {
                    webhook_id: row.get(0)?,
                    workflow_name: row.get(1)?,
                    workflow_active: row.get(2)?,
                    events,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Count the total number of Jira trigger rows.
    pub fn count_jira_triggers(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM jira_triggers", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    // ── Slack triggers ──────────────────────────────────────────────────

    /// Replace all Slack trigger rows with the supplied set.
    pub fn sync_slack_triggers(
        &self,
        triggers: &[SlackTriggerConfig],
    ) -> Result<(), rusqlite::Error> {
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM slack_triggers", [])?;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO slack_triggers \
                 (webhook_id, workflow_id, workflow_name, workflow_active, event_type, channels, watch_whole_workspace) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;
            for t in triggers {
                let channels_json =
                    serde_json::to_string(&t.channels).unwrap_or_else(|_| "[]".to_string());
                stmt.execute(rusqlite::params![
                    t.webhook_id,
                    t.workflow_id,
                    t.workflow_name,
                    t.workflow_active,
                    t.event_type,
                    channels_json,
                    t.watch_whole_workspace,
                ])?;
            }
        }
        tx.commit()?;
        debug!(count = triggers.len(), "Synced Slack triggers to database");
        Ok(())
    }

    /// Query all Slack triggers.
    pub fn query_slack_triggers(&self) -> Result<Vec<SlackTriggerRow>, rusqlite::Error> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT webhook_id, workflow_name, workflow_active, \
                    event_type, channels, watch_whole_workspace \
             FROM slack_triggers",
        )?;
        let rows = stmt
            .query_map([], |row| {
                let channels_json: String = row.get(4)?;
                let channels: Vec<String> =
                    serde_json::from_str(&channels_json).unwrap_or_default();
                Ok(SlackTriggerRow {
                    webhook_id: row.get(0)?,
                    workflow_name: row.get(1)?,
                    workflow_active: row.get(2)?,
                    event_type: row.get(3)?,
                    channels,
                    watch_whole_workspace: row.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Count the total number of Slack trigger rows.
    pub fn count_slack_triggers(&self) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock();
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM slack_triggers", [], |row| row.get(0))?;
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_memory_db() -> Database {
        Database::open(":memory:").expect("in-memory DB should open")
    }

    // ── webhook_secrets tests ───────────────────────────────────────────

    #[test]
    fn test_upsert_webhook_secret_insert() {
        let db = open_memory_db();
        let id = db
            .upsert_webhook_secret("wh1", "github", "secret-abc")
            .unwrap();
        assert!(id > 0);
    }

    #[test]
    fn test_upsert_webhook_secret_update_preserves_id() {
        let db = open_memory_db();
        let id1 = db
            .upsert_webhook_secret("wh1", "github", "old-secret")
            .unwrap();
        let id2 = db
            .upsert_webhook_secret("wh1", "github", "new-secret")
            .unwrap();
        assert_eq!(id1, id2, "ID should be stable across updates");
    }

    #[test]
    fn test_upsert_webhook_secret_fallback_does_not_overwrite() {
        let db = open_memory_db();
        let _id = db
            .upsert_webhook_secret("wh1", "github", "provider-captured")
            .unwrap();
        db.upsert_webhook_secret_fallback("wh1", "github", "static-data-secret")
            .unwrap();

        // Verify the original secret is preserved
        let conn = db.conn.lock();
        let secret: String = conn
            .query_row(
                "SELECT secret FROM webhook_secrets WHERE webhook_id = 'wh1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(secret, "provider-captured");
    }

    #[test]
    fn test_upsert_webhook_secret_fallback_inserts_when_absent() {
        let db = open_memory_db();
        db.upsert_webhook_secret_fallback("wh1", "github", "static-data-secret")
            .unwrap();

        let conn = db.conn.lock();
        let secret: String = conn
            .query_row(
                "SELECT secret FROM webhook_secrets WHERE webhook_id = 'wh1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(secret, "static-data-secret");
    }

    #[test]
    fn test_delete_webhook_secret_by_id() {
        let db = open_memory_db();
        let id = db.upsert_webhook_secret("wh1", "github", "secret").unwrap();
        assert!(db.delete_webhook_secret_by_id(id).unwrap());
        assert!(!db.delete_webhook_secret_by_id(id).unwrap()); // second delete returns false
    }

    // ── github_triggers tests ───────────────────────────────────────────

    #[test]
    fn test_sync_and_query_github_triggers() {
        let db = open_memory_db();

        let triggers = vec![GitHubTriggerConfig {
            webhook_id: "wh1".to_string(),
            workflow_id: "wf1".to_string(),
            workflow_name: "Test".to_string(),
            workflow_active: true,
            events: vec!["push".to_string()],
            owner: "test-owner".to_string(),
            repository: "test-repo".to_string(),
            webhook_secret: None,
        }];

        db.sync_github_triggers(&triggers).unwrap();

        let rows = db
            .query_github_triggers(Some("test-owner"), Some("test-repo"))
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].webhook_id, "wh1");
        assert_eq!(rows[0].events, vec!["push"]);
        assert!(rows[0].secret.is_none());
    }

    #[test]
    fn test_github_query_joins_webhook_secret() {
        let db = open_memory_db();

        db.upsert_webhook_secret("wh1", "github", "the-secret")
            .unwrap();

        let triggers = vec![GitHubTriggerConfig {
            webhook_id: "wh1".to_string(),
            workflow_id: "wf1".to_string(),
            workflow_name: "Test".to_string(),
            workflow_active: true,
            events: vec!["push".to_string()],
            owner: "test-owner".to_string(),
            repository: "test-repo".to_string(),
            webhook_secret: None,
        }];
        db.sync_github_triggers(&triggers).unwrap();

        let rows = db
            .query_github_triggers(Some("test-owner"), Some("test-repo"))
            .unwrap();
        assert_eq!(rows[0].secret.as_deref(), Some("the-secret"));
    }

    #[test]
    fn test_github_query_case_insensitive() {
        let db = open_memory_db();

        let triggers = vec![GitHubTriggerConfig {
            webhook_id: "wh1".to_string(),
            workflow_id: "wf1".to_string(),
            workflow_name: "Test".to_string(),
            workflow_active: true,
            events: vec!["push".to_string()],
            owner: "Test-Owner".to_string(),
            repository: "Test-Repo".to_string(),
            webhook_secret: None,
        }];
        db.sync_github_triggers(&triggers).unwrap();

        let rows = db
            .query_github_triggers(Some("test-owner"), Some("test-repo"))
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn test_sync_replaces_all_github_triggers() {
        let db = open_memory_db();

        let triggers1 = vec![GitHubTriggerConfig {
            webhook_id: "wh-old".to_string(),
            workflow_id: "wf-old".to_string(),
            workflow_name: "Old".to_string(),
            workflow_active: true,
            events: vec!["push".to_string()],
            owner: "o".to_string(),
            repository: "r".to_string(),
            webhook_secret: None,
        }];
        db.sync_github_triggers(&triggers1).unwrap();
        assert_eq!(db.count_github_triggers().unwrap(), 1);

        let triggers2 = vec![GitHubTriggerConfig {
            webhook_id: "wh-new".to_string(),
            workflow_id: "wf-new".to_string(),
            workflow_name: "New".to_string(),
            workflow_active: true,
            events: vec!["issues".to_string()],
            owner: "o".to_string(),
            repository: "r".to_string(),
            webhook_secret: None,
        }];
        db.sync_github_triggers(&triggers2).unwrap();
        assert_eq!(db.count_github_triggers().unwrap(), 1);

        let rows = db.query_github_triggers(Some("o"), Some("r")).unwrap();
        assert_eq!(rows[0].webhook_id, "wh-new");
    }

    // ── jira_triggers tests ─────────────────────────────────────────────

    #[test]
    fn test_sync_and_query_jira_triggers() {
        let db = open_memory_db();

        let triggers = vec![JiraTriggerConfig {
            webhook_id: "jh1".to_string(),
            workflow_id: "wf1".to_string(),
            workflow_name: "Jira Test".to_string(),
            workflow_active: true,
            events: vec!["jira:issue_created".to_string()],
        }];
        db.sync_jira_triggers(&triggers).unwrap();

        let rows = db.query_jira_triggers().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].webhook_id, "jh1");
        assert_eq!(rows[0].events, vec!["jira:issue_created"]);
    }

    // ── slack_triggers tests ────────────────────────────────────────────

    #[test]
    fn test_sync_and_query_slack_triggers() {
        let db = open_memory_db();

        let triggers = vec![SlackTriggerConfig {
            webhook_id: "sh1".to_string(),
            workflow_id: "wf1".to_string(),
            workflow_name: "Slack Test".to_string(),
            workflow_active: true,
            event_type: "message".to_string(),
            channels: vec!["C123".to_string()],
            watch_whole_workspace: false,
        }];
        db.sync_slack_triggers(&triggers).unwrap();

        let rows = db.query_slack_triggers().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "message");
        assert_eq!(rows[0].channels, vec!["C123"]);
        assert!(!rows[0].watch_whole_workspace);
    }
}
