const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const initSqlJs = require('sql.js');

// /tmp keeps an unconfigured development run writable in restricted containers.
// Production should set PANEL_DB_PATH to a 0600 path under the project runtime directory.
const DEFAULT_DB_PATH = path.join('/tmp', 'gpt-register-panel', 'panel.sqlite3');

function jsonString(value) {
  return JSON.stringify(value === undefined ? null : value);
}

function randomId(prefix) {
  return prefix + '_' + crypto.randomBytes(12).toString('hex');
}

function sqlString(value) {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'boolean') return value ? '1' : '0';
  return "'" + String(value).replaceAll("'", "''") + "'";
}

function resultRows(result) {
  if (!result || result.length === 0) return [];
  const [{ columns, values }] = result;
  return values.map((row) => Object.fromEntries(columns.map((column, index) => [column, row[index]])));
}

class PanelDb {
  constructor(dbPath = process.env.PANEL_DB_PATH || DEFAULT_DB_PATH) {
    this.dbPath = path.resolve(dbPath);
    this.queue = Promise.resolve();
    this.ready = this.initialize();
  }

  async initialize() {
    fs.mkdirSync(path.dirname(this.dbPath), { recursive: true, mode: 0o700 });
    const SQL = await initSqlJs({
      locateFile: (file) => path.join(path.dirname(require.resolve('sql.js')), file),
    });
    const bytes = fs.existsSync(this.dbPath) ? fs.readFileSync(this.dbPath) : null;
    this.database = bytes ? new SQL.Database(bytes) : new SQL.Database();
    this.database.run(`
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS sync_snapshots (
        id TEXT PRIMARY KEY,
        version TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        summary_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sync_snapshots_created_at ON sync_snapshots(created_at DESC);
      CREATE TABLE IF NOT EXISTS sync_jobs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        requested_by TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        result_json TEXT,
        error TEXT,
        created_at TEXT NOT NULL,
        started_at TEXT,
        finished_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_sync_jobs_created_at ON sync_jobs(created_at DESC);
      CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        job_id TEXT,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target_key TEXT,
        before_fingerprint TEXT,
        after_fingerprint TEXT,
        result TEXT NOT NULL,
        details_json TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_audit_events_created_at ON audit_events(created_at DESC);
      CREATE TABLE IF NOT EXISTS account_links (
        identity_key TEXT PRIMARY KEY,
        token_path TEXT,
        sub2api_id INTEGER,
        account_name TEXT,
        updated_at TEXT NOT NULL
      );
    `);
    await this.persist();
  }

  async persist() {
    const bytes = this.database.export();
    const temporaryPath = this.dbPath + '.tmp-' + process.pid;
    fs.writeFileSync(temporaryPath, Buffer.from(bytes), { mode: 0o600 });
    fs.renameSync(temporaryPath, this.dbPath);
    try { fs.chmodSync(this.dbPath, 0o600); } catch {}
  }

  async write(callback) {
    await this.ready;
    const run = this.queue.then(async () => {
      const result = await callback(this.database);
      await this.persist();
      return result;
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async read(callback) {
    await this.ready;
    await this.queue;
    return callback(this.database);
  }

  saveSnapshot(snapshot) {
    const id = randomId('snap');
    const now = new Date().toISOString();
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO sync_snapshots
        (id, version, generated_at, summary_json, created_at)
        VALUES (?, ?, ?, ?, ?)`);
      statement.run([
        id,
        snapshot.version,
        snapshot.generatedAt,
        jsonString({ counts: snapshot.diff?.counts || {}, summary: snapshot.sources?.summary || {} }),
        now,
      ]);
      statement.free();
      return id;
    });
  }

  createJob(type, payload = {}, requestedBy = 'local') {
    const id = randomId('job');
    const now = new Date().toISOString();
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO sync_jobs
        (id, type, status, requested_by, payload_json, created_at)
        VALUES (?, ?, 'queued', ?, ?, ?)`);
      statement.run([id, type, requestedBy, jsonString(payload), now]);
      statement.free();
      return { id, type, status: 'queued', requestedBy, createdAt: now };
    });
  }

  updateJob(id, patch = {}) {
    const fields = [];
    const values = [];
    const add = (column, value) => {
      if (value === undefined) return;
      fields.push(column + ' = ?');
      values.push(value);
    };
    add('status', patch.status);
    add('result_json', patch.result === undefined ? undefined : jsonString(patch.result));
    add('error', patch.error);
    add('started_at', patch.startedAt);
    add('finished_at', patch.finishedAt);
    if (fields.length === 0) return Promise.resolve();
    values.push(id);
    return this.write((database) => {
      const statement = database.prepare('UPDATE sync_jobs SET ' + fields.join(', ') + ' WHERE id = ?');
      statement.run(values);
      statement.free();
    });
  }

  decodeJob(row) {
    if (!row) return null;
    let payload = null;
    let result = null;
    try { payload = JSON.parse(row.payload_json); } catch {}
    try { result = row.result_json ? JSON.parse(row.result_json) : null; } catch {}
    return {
      id: row.id,
      type: row.type,
      status: row.status,
      requestedBy: row.requested_by,
      payload,
      result,
      error: row.error || null,
      createdAt: row.created_at,
      startedAt: row.started_at || null,
      finishedAt: row.finished_at || null,
    };
  }

  async getJob(id) {
    const rows = await this.read((database) => resultRows(database.exec(
      'SELECT * FROM sync_jobs WHERE id = ' + sqlString(id) + ' LIMIT 1',
    )));
    return this.decodeJob(rows[0]);
  }

  async listJobs(limit = 50) {
    const safeLimit = Math.max(1, Math.min(200, Number(limit) || 50));
    const rows = await this.read((database) => resultRows(database.exec(
      'SELECT * FROM sync_jobs ORDER BY created_at DESC LIMIT ' + safeLimit,
    )));
    return rows.map((row) => this.decodeJob(row));
  }

  audit(event = {}) {
    const now = new Date().toISOString();
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO audit_events
        (job_id, actor, action, target_key, before_fingerprint, after_fingerprint, result, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      statement.run([
        event.jobId || null,
        event.actor || 'local',
        event.action || 'unknown',
        event.targetKey || null,
        event.beforeFingerprint || null,
        event.afterFingerprint || null,
        event.result || 'ok',
        jsonString(event.details || {}),
        now,
      ]);
      statement.free();
    });
  }

  async listAudit(limit = 100) {
    const safeLimit = Math.max(1, Math.min(500, Number(limit) || 100));
    const rows = await this.read((database) => resultRows(database.exec(
      'SELECT * FROM audit_events ORDER BY id DESC LIMIT ' + safeLimit,
    )));
    return rows.map((row) => {
      let details = {};
      try { details = JSON.parse(row.details_json || '{}'); } catch {}
      return {
        id: row.id,
        jobId: row.job_id || null,
        actor: row.actor,
        action: row.action,
        targetKey: row.target_key || null,
        beforeFingerprint: row.before_fingerprint || null,
        afterFingerprint: row.after_fingerprint || null,
        result: row.result,
        details,
        createdAt: row.created_at,
      };
    });
  }

  saveLink(link = {}) {
    if (!link.identityKey) return Promise.resolve();
    const now = new Date().toISOString();
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO account_links
        (identity_key, token_path, sub2api_id, account_name, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(identity_key) DO UPDATE SET
          token_path=excluded.token_path, sub2api_id=excluded.sub2api_id,
          account_name=excluded.account_name, updated_at=excluded.updated_at`);
      statement.run([
        link.identityKey,
        link.tokenPath || null,
        link.sub2apiId || null,
        link.accountName || null,
        now,
      ]);
      statement.free();
    });
  }
}

module.exports = {
  PanelDb,
  DEFAULT_DB_PATH,
};
