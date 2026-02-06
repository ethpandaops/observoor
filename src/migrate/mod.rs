use anyhow::{Context, Result};
use clickhouse_rs::Pool;

/// Embedded SQL migration with version, direction, and content.
struct Migration {
    version: u32,
    up_sql: &'static str,
    down_sql: &'static str,
}

/// All embedded migrations, ordered by version.
static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        up_sql: include_str!("sql/001_init.up.sql"),
        down_sql: include_str!("sql/001_init.down.sql"),
    },
    Migration {
        version: 2,
        up_sql: include_str!("sql/002_drop_raw_events.up.sql"),
        down_sql: include_str!("sql/002_drop_raw_events.down.sql"),
    },
];

/// Manages ClickHouse schema migrations.
///
/// Compatible with golang-migrate's `schema_migrations` table format.
/// Embeds SQL files from `internal/migrate/sql/` and applies them in order.
pub trait Migrator: Send {
    /// Applies all pending forward migrations.
    fn up(&self) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Rolls back the last applied migration.
    fn down(&self) -> impl std::future::Future<Output = Result<()>> + Send;

    /// Returns the current migration version and dirty flag.
    fn status(&self) -> impl std::future::Future<Output = Result<(u32, bool)>> + Send;
}

/// ClickHouse migration runner.
pub struct ClickHouseMigrator {
    pool: Pool,
}

impl ClickHouseMigrator {
    /// Creates a new migrator using the given connection pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }

    /// Ensures the schema_migrations tracking table exists.
    async fn ensure_migrations_table(&self) -> Result<()> {
        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting ClickHouse handle for migrations table")?;

        handle
            .execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations (
                    version Int64,
                    dirty UInt8,
                    sequence UInt64
                ) ENGINE = TinyLog",
            )
            .await
            .context("creating schema_migrations table")?;

        Ok(())
    }

    /// Returns the current migration version and dirty state.
    async fn current_version(&self) -> Result<(u32, bool)> {
        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting ClickHouse handle for version check")?;

        let block = handle
            .query("SELECT version, dirty FROM schema_migrations ORDER BY sequence DESC LIMIT 1")
            .fetch_all()
            .await
            .context("querying migration version")?;

        if block.row_count() == 0 {
            return Ok((0, false));
        }

        let row = block.rows().next();
        match row {
            Some(row) => {
                let version: i64 = row.get("version").context("reading version")?;
                let dirty: u8 = row.get("dirty").context("reading dirty flag")?;
                Ok((version as u32, dirty != 0))
            }
            None => Ok((0, false)),
        }
    }

    /// Sets the migration version in the tracking table.
    async fn set_version(&self, version: u32, dirty: bool) -> Result<()> {
        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting ClickHouse handle for version update")?;

        // Truncate and re-insert (matches golang-migrate behavior).
        handle
            .execute("TRUNCATE TABLE schema_migrations")
            .await
            .context("truncating schema_migrations")?;

        let dirty_val: u8 = if dirty { 1 } else { 0 };
        let sql = format!(
            "INSERT INTO schema_migrations (version, dirty, sequence) VALUES ({version}, {dirty_val}, 1)"
        );

        handle
            .execute(sql.as_str())
            .await
            .context("inserting migration version")?;

        Ok(())
    }

    /// Splits a SQL string into individual statements and executes each.
    async fn execute_sql(&self, sql: &str) -> Result<()> {
        let mut handle = self
            .pool
            .get_handle()
            .await
            .context("getting ClickHouse handle for SQL execution")?;

        for statement in split_statements(sql) {
            handle.execute(statement).await.with_context(|| {
                let preview: String = statement.chars().take(80).collect();
                format!("executing migration statement: {preview}...")
            })?;
        }

        Ok(())
    }
}

impl Migrator for ClickHouseMigrator {
    async fn up(&self) -> Result<()> {
        self.ensure_migrations_table().await?;

        let (current_version, dirty) = self.current_version().await?;

        if dirty {
            anyhow::bail!(
                "migration version {current_version} is dirty, manual intervention required"
            );
        }

        tracing::info!(current_version, "running migrations");

        let mut applied = 0u32;

        for migration in MIGRATIONS {
            if migration.version <= current_version {
                continue;
            }

            tracing::info!(version = migration.version, "applying migration");

            // Mark as dirty before applying.
            self.set_version(migration.version, true).await?;

            // Execute the migration SQL.
            self.execute_sql(migration.up_sql)
                .await
                .with_context(|| format!("applying migration version {}", migration.version))?;

            // Mark as clean.
            self.set_version(migration.version, false).await?;

            applied += 1;
        }

        if applied == 0 {
            tracing::info!("no pending migrations");
        } else {
            let (final_version, _) = self.current_version().await?;
            tracing::info!(version = final_version, applied, "migrations completed");
        }

        Ok(())
    }

    async fn down(&self) -> Result<()> {
        self.ensure_migrations_table().await?;

        let (current_version, _) = self.current_version().await?;

        if current_version == 0 {
            tracing::info!("no migrations to roll back");
            return Ok(());
        }

        // Find the migration matching current version.
        let migration = MIGRATIONS
            .iter()
            .find(|m| m.version == current_version)
            .with_context(|| format!("migration version {current_version} not found"))?;

        tracing::info!(version = current_version, "rolling back migration");

        // Mark as dirty.
        self.set_version(current_version, true).await?;

        // Execute the down SQL.
        self.execute_sql(migration.down_sql)
            .await
            .with_context(|| format!("rolling back migration version {current_version}"))?;

        // Set version to previous migration.
        let prev_version = MIGRATIONS
            .iter()
            .filter(|m| m.version < current_version)
            .map(|m| m.version)
            .max()
            .unwrap_or(0);

        if prev_version == 0 {
            // No previous version, truncate tracking table.
            let mut handle = self.pool.get_handle().await?;
            handle
                .execute("TRUNCATE TABLE schema_migrations")
                .await
                .context("truncating schema_migrations after rollback")?;
        } else {
            self.set_version(prev_version, false).await?;
        }

        tracing::info!(version = prev_version, "rollback completed");

        Ok(())
    }

    async fn status(&self) -> Result<(u32, bool)> {
        self.ensure_migrations_table().await?;
        self.current_version().await
    }
}

/// Splits SQL text into individual statements by semicolons.
///
/// Handles empty lines, comments, and whitespace-only segments.
fn split_statements(sql: &str) -> Vec<&str> {
    sql.split(';')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_statements_basic() {
        let sql = "CREATE TABLE foo (id Int32); CREATE TABLE bar (id Int32);";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 2);
        assert!(stmts[0].starts_with("CREATE TABLE foo"));
        assert!(stmts[1].starts_with("CREATE TABLE bar"));
    }

    #[test]
    fn test_split_statements_with_whitespace() {
        let sql = "
            SELECT 1;

            SELECT 2;

        ";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 2);
    }

    #[test]
    fn test_split_statements_empty() {
        let stmts = split_statements("");
        assert!(stmts.is_empty());
    }

    #[test]
    fn test_split_statements_trailing_semicolons() {
        let sql = "SELECT 1;;;";
        let stmts = split_statements(sql);
        assert_eq!(stmts.len(), 1);
    }

    #[test]
    fn test_migrations_embedded() {
        // Verify that embedded SQL files are non-empty.
        for m in MIGRATIONS {
            assert!(m.version > 0);
            assert!(
                !m.up_sql.is_empty(),
                "migration {} up SQL is empty",
                m.version
            );
            assert!(
                !m.down_sql.is_empty(),
                "migration {} down SQL is empty",
                m.version
            );
        }
    }

    #[test]
    fn test_migrations_ordered() {
        for window in MIGRATIONS.windows(2) {
            assert!(
                window[0].version < window[1].version,
                "migrations not in order: {} >= {}",
                window[0].version,
                window[1].version,
            );
        }
    }
}
