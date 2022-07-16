use std::ops::Sub;
use std::time::{Duration, SystemTime, SystemTimeError, UNIX_EPOCH};

use sqlite::Connection;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Clone)]
pub struct StoreError {
    message: String,
}

pub struct LogEntry {
    pub timestamp: u64,
    pub host: String,
}

pub trait DnsLogStore {
    fn clean_up(&mut self);
    fn on_query(&mut self, host: &str) -> Result<()>;
    fn load_entries(&self) -> Result<Vec<LogEntry>>;
}

struct SQLiteDnsLogStore {
    conn: Connection,
}

pub fn init_dns_log_store(path: &str) -> Result<Box<dyn DnsLogStore>> {
    let conn = sqlite::open(path)?;
    let mut store = SQLiteDnsLogStore { conn };
    store.init_db()?;
    Ok(Box::new(store))
}

impl SQLiteDnsLogStore {
    fn init_db(&mut self) -> Result<()> {
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS dns_log (timestamp INTEGER, host TEXT);
            CREATE UNIQUE INDEX IF NOT EXISTS uniq_host ON dns_log (host);
            ",
        )?;
        Ok(())
    }
}

impl DnsLogStore for SQLiteDnsLogStore {
    fn clean_up(&mut self) {
        todo!()
    }

    fn on_query(&mut self, host: &str) -> Result<()> {
        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH)?;
        let timestamp = duration.as_secs();
        let mut statement = self.conn.prepare(
            "INSERT INTO dns_log (timestamp, host) VALUES (?, ?)\
            ON CONFLICT(host) DO UPDATE SET timestamp=excluded.timestamp;
            ",
        )?;
        statement.bind(1, timestamp as i64)?;
        statement.bind(2, host)?;
        statement.next()?;
        Ok(())
    }

    fn load_entries(&self) -> Result<Vec<LogEntry>> {
        let mut entries: Vec<LogEntry> = Vec::new();
        let mut statement = self
            .conn
            .prepare("SELECT timestamp, host FROM dns_log WHERE timestamp > ?")?;
        let now = SystemTime::now();
        let duration = now
            .duration_since(UNIX_EPOCH)?
            .sub(Duration::from_secs(86400 * 7));
        let recent_timestamp = duration.as_secs() as i64;
        statement.bind(1, recent_timestamp)?;
        let mut cursor = statement.into_cursor();
        while let Some(row) = cursor.next()? {
            let timestamp = row[0].as_integer().unwrap_or(0) as u64;
            let host = row[1].as_string().unwrap_or("");
            if timestamp != 0 && !host.is_empty() {
                entries.push(LogEntry {
                    timestamp,
                    host: host.to_string(),
                })
            }
        }
        Ok(entries)
    }
}

impl From<SystemTimeError> for StoreError {
    fn from(e: SystemTimeError) -> Self {
        StoreError {
            message: e.to_string(),
        }
    }
}

impl From<sqlite::Error> for StoreError {
    fn from(e: sqlite::Error) -> Self {
        StoreError {
            message: e.message.unwrap_or("sqlite error".to_string()),
        }
    }
}
