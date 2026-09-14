const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const initSqlJs = require('sql.js');
const { redactText, redactValue } = require('./logger');
const { acquireBakeryLease, releaseBakeryLease } = require('./lib/bakeryLock');
const { ensureDirectoryTree } = require('./lib/safeFs');
const { currentProcessOwner, isProcessOwnerAlive } = require('./taskCoordinator');

// /tmp keeps an unconfigured development run writable in restricted containers.
// Production should set PANEL_DB_PATH to a 0600 path under the project runtime directory.
const DEFAULT_DB_PATH = path.join('/tmp', 'gpt-register-panel', 'panel.sqlite3');
const initializationPromises = new Map();
const DB_LOCK_KIND = 'gpt-register-panel-db-lock';
const DEFAULT_DB_MAX_BYTES = 128 * 1024 * 1024;
const HARD_DB_MAX_BYTES = 512 * 1024 * 1024;
const MAX_JOB_PAYLOAD_BYTES = 1024 * 1024;
const MAX_JOB_RESULT_BYTES = 2 * 1024 * 1024;
const MAX_JOB_ERROR_BYTES = 64 * 1024;
const MAX_AUDIT_TEXT_BYTES = 16 * 1024;
const MAX_AUDIT_DETAILS_BYTES = 512 * 1024;
const ACTIVE_JOB_STATUSES = new Set(['queued', 'running']);
const TERMINAL_JOB_STATUSES = new Set(['succeeded', 'partial', 'failed', 'interrupted']);
const JOB_STATUSES = new Set([...ACTIVE_JOB_STATUSES, ...TERMINAL_JOB_STATUSES]);

function sameInode(left, right) {
  return Boolean(left && right && left.dev === right.dev && left.ino === right.ino);
}

function databaseMaximumBytes() {
  const value = Number(process.env.PANEL_DB_MAX_BYTES);
  if (!Number.isSafeInteger(value) || value < 1024 * 1024) return DEFAULT_DB_MAX_BYTES;
  return Math.min(value, HARD_DB_MAX_BYTES);
}

function readDatabaseBytes(descriptor, maximumBytes) {
  const chunks = [];
  let total = 0;
  while (total <= maximumBytes) {
    const buffer = Buffer.allocUnsafe(Math.min(64 * 1024, maximumBytes + 1 - total));
    const bytesRead = fs.readSync(descriptor, buffer, 0, buffer.length, null);
    if (bytesRead === 0) break;
    chunks.push(Buffer.from(buffer.subarray(0, bytesRead)));
    total += bytesRead;
  }
  if (total > maximumBytes) {
    const error = new Error('SQLite 数据库文件超过安全上限');
    error.code = 'PANEL_DB_TOO_LARGE';
    throw error;
  }
  return Buffer.concat(chunks, total);
}

function storedJobOwnerIsAlive(job) {
  const verifier = currentProcessOwner();
  // Legacy rows without the identity dimensions available on this host cannot
  // prove that a reused PID still belongs to the process that queued the job.
  if (verifier.processStartId && !String(job?.owner_start_id || '').trim()) return false;
  if (verifier.processBootId && !String(job?.owner_boot_id || '').trim()) return false;
  return isProcessOwnerAlive(job?.owner_pid, job?.owner_start_id, job?.owner_boot_id);
}

function jsonString(value) {
  return JSON.stringify(value === undefined ? null : value);
}

function assertStoredByteLength(field, value, maximumBytes) {
  if (value === null || value === undefined) return value;
  const actualBytes = Buffer.byteLength(String(value), 'utf8');
  if (actualBytes <= maximumBytes) return value;
  const error = new Error('SQLite 字段超过安全字节上限');
  error.code = 'PANEL_DB_FIELD_TOO_LARGE';
  error.field = field;
  error.actualBytes = actualBytes;
  error.maximumBytes = maximumBytes;
  throw error;
}

function boundedJsonString(field, value, maximumBytes) {
  return assertStoredByteLength(field, jsonString(redactValue(value)), maximumBytes);
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
    this.lockPath = this.dbPath + '.lock';
    this.queue = Promise.resolve();
    const existingInitialization = initializationPromises.get(this.dbPath);
    if (existingInitialization) {
      // Multiple PanelDb objects in one process are used by tests and by
      // embedded consumers. Only the first object performs restart recovery;
      // later objects load the already-recovered file without resetting jobs.
      this.ready = existingInitialization.then(() => this.initializeLocalDatabase());
    } else {
      const initialization = this.initialize();
      const wrappedInitialization = initialization.then((result) => {
        return result;
      }).catch((error) => {
        throw error;
      });
      this.ready = wrappedInitialization;
      // Store the wrapped promise so a concurrent constructor waits for the
      // completion path that records initialization success/failure.
      initializationPromises.set(this.dbPath, wrappedInitialization);
      wrappedInitialization.then(
        () => { if (initializationPromises.get(this.dbPath) === wrappedInitialization) initializationPromises.delete(this.dbPath); },
        () => { if (initializationPromises.get(this.dbPath) === wrappedInitialization) initializationPromises.delete(this.dbPath); },
      );
    }
  }

  pinDatabaseDirectory() {
    const directory = path.dirname(this.dbPath);
    const realPath = fs.realpathSync(directory);
    let descriptor;
    try {
      descriptor = fs.openSync(
        realPath,
        fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0),
      );
      const stat = fs.fstatSync(descriptor);
      if (!stat.isDirectory()) throw new Error('SQLite 数据库父路径必须是目录');
      const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
      if ((currentUid !== null && stat.uid !== currentUid) || (stat.mode & 0o022) !== 0) {
        const error = new Error('SQLite 数据库父目录必须由当前用户持有且不可由组或其他用户写入');
        error.code = 'DB_LOCK_PATH_INVALID';
        throw error;
      }
      try {
        const descriptorRealPath = fs.realpathSync('/proc/self/fd/' + descriptor);
        if (descriptorRealPath !== realPath) throw new Error('SQLite 数据库父目录解析结果不一致');
      } catch (error) {
        if (process.platform === 'linux') throw error;
        const latest = fs.lstatSync(realPath);
        if (!latest.isDirectory() || !sameInode(latest, stat)) {
          throw new Error('SQLite 数据库父目录在固定期间发生变化');
        }
      }
      if (this.databaseDirectoryIdentity
          && (!sameInode(this.databaseDirectoryIdentity, stat)
            || this.databaseDirectoryIdentity.realPath !== realPath)) {
        throw new Error('SQLite 数据库父目录已被替换，拒绝继续读写');
      }
      this.databaseDirectoryIdentity = { realPath, dev: stat.dev, ino: stat.ino };
      this.lockPath = path.join(realPath, path.basename(this.dbPath) + '.lock');
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
    }
  }

  openPinnedDatabaseDirectory() {
    if (!this.databaseDirectoryIdentity) this.pinDatabaseDirectory();
    const identity = this.databaseDirectoryIdentity;
    const descriptor = fs.openSync(
      identity.realPath,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY || 0) | (fs.constants.O_NOFOLLOW || 0),
    );
    try {
      const stat = fs.fstatSync(descriptor);
      if (!stat.isDirectory() || !sameInode(identity, stat)) {
        throw new Error('SQLite 数据库父目录已被替换，拒绝继续读写');
      }
      if (process.platform === 'linux') {
        const accessDirectory = '/proc/self/fd/' + descriptor;
        if (fs.realpathSync(accessDirectory) !== identity.realPath) {
          throw new Error('SQLite 数据库父目录 FD 校验失败');
        }
        return { descriptor, accessDirectory };
      }
      const latest = fs.lstatSync(identity.realPath);
      if (!latest.isDirectory() || !sameInode(identity, latest)) {
        throw new Error('SQLite 数据库父目录已被替换，拒绝继续读写');
      }
      return { descriptor, accessDirectory: identity.realPath };
    } catch (error) {
      try { fs.closeSync(descriptor); } catch {}
      throw error;
    }
  }

  async acquireFileLock() {
    const pinnedDirectory = this.openPinnedDatabaseDirectory();
    const timeoutMs = Math.max(1000, Math.min(120000, Number(process.env.PANEL_DB_LOCK_TIMEOUT_MS) || 30000));
    const owner = currentProcessOwner();
    try {
      const lease = await acquireBakeryLease({
        directoryDescriptor: pinnedDirectory.descriptor,
        accessDirectory: pinnedDirectory.accessDirectory,
        lockName: path.basename(this.dbPath) + '.lock',
        kind: DB_LOCK_KIND,
        owner,
        isOwnerAlive: isProcessOwnerAlive,
        timeoutMs,
        pollMs: 25,
        invalidCode: 'DB_LOCK_PATH_INVALID',
        changedCode: 'DB_LOCK_CHANGED',
        timeoutCode: 'DB_LOCK_TIMEOUT',
        releaseCode: 'DB_LOCK_RELEASE_FAILED',
        invalidMessage: 'SQLite 锁命名空间或租约记录无效，拒绝覆盖或删除',
        changedMessage: 'SQLite 锁租约在操作期间发生变化',
        timeoutMessage: 'SQLite 文件锁等待超时',
        releaseMessage: 'SQLite 锁租约释放失败，当前进程已停止使用该数据库锁命名空间',
      });
      return { ...lease, directoryDescriptor: pinnedDirectory.descriptor };
    } catch (error) {
      try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
      throw error;
    }
  }

  releaseFileLock(lease) {
    try {
      releaseBakeryLease(lease);
      if (lease.directoryDescriptor !== undefined) fs.fsyncSync(lease.directoryDescriptor);
    } finally {
      if (lease?.directoryDescriptor !== undefined) {
        try { fs.closeSync(lease.directoryDescriptor); } catch {}
      }
    }
  }

  async withFileLock(callback) {
    const lease = await this.acquireFileLock();
    try {
      return await callback();
    } finally {
      this.releaseFileLock(lease);
    }
  }

  loadDatabaseFromDisk() {
    const pinnedDirectory = this.openPinnedDatabaseDirectory();
    let descriptor;
    let bytes = null;
    try {
      const pinnedPath = path.join(pinnedDirectory.accessDirectory, path.basename(this.dbPath));
      try {
        descriptor = fs.openSync(pinnedPath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0));
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
      if (descriptor !== undefined) {
        const before = fs.fstatSync(descriptor);
        const currentUid = typeof process.getuid === 'function' ? process.getuid() : null;
        if (!before.isFile() || before.nlink !== 1
            || (currentUid !== null && before.uid !== currentUid)
            || (before.mode & 0o077) !== 0) {
          throw new Error('PANEL_DB_PATH 必须是当前用户持有的 0600 非硬链接普通文件');
        }
        if (before.size > databaseMaximumBytes()) {
          const error = new Error('SQLite 数据库文件超过安全上限');
          error.code = 'PANEL_DB_TOO_LARGE';
          throw error;
        }
        bytes = readDatabaseBytes(descriptor, databaseMaximumBytes());
        const after = fs.fstatSync(descriptor);
        if (!sameInode(before, after)
            || before.size !== after.size
            || before.mtimeMs !== after.mtimeMs
            || before.ctimeMs !== after.ctimeMs
            || bytes.length !== after.size) {
          throw new Error('SQLite 数据库文件在读取期间发生变化');
        }
      }
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
    }
    const next = bytes ? new this.SQL.Database(bytes) : new this.SQL.Database();
    if (this.database && typeof this.database.close === 'function') {
      try { this.database.close(); } catch {}
    }
    this.database = next;
  }

  runSchema() {
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
        finished_at TEXT,
        claim_keys_json TEXT,
        owner_pid INTEGER,
        owner_start_id TEXT,
        owner_boot_id TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_sync_jobs_created_at ON sync_jobs(created_at DESC);
      CREATE TABLE IF NOT EXISTS job_claims (
        claim_key TEXT PRIMARY KEY,
        job_id TEXT NOT NULL,
        job_type TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_job_claims_job_id ON job_claims(job_id);
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
    const columns = resultRows(this.database.exec('PRAGMA table_info(sync_jobs)'))
      .map((row) => row.name);
    if (!columns.includes('claim_keys_json')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN claim_keys_json TEXT');
    }
    if (!columns.includes('owner_pid')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN owner_pid INTEGER');
    }
    if (!columns.includes('owner_start_id')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN owner_start_id TEXT');
    }
    if (!columns.includes('owner_boot_id')) {
      this.database.run('ALTER TABLE sync_jobs ADD COLUMN owner_boot_id TEXT');
    }
  }

  pruneRows() {
    const maxJobs = Math.max(100, Math.min(100000, Number(process.env.PANEL_MAX_JOBS) || 5000));
    const maxAudit = Math.max(100, Math.min(200000, Number(process.env.PANEL_MAX_AUDIT_EVENTS) || 20000));
    const maxSnapshots = Math.max(20, Math.min(10000, Number(process.env.PANEL_MAX_SNAPSHOTS) || 500));
    // Never prune a queued/running job: its claim is the guard that prevents
    // duplicate remote work. Terminal history is expendable; active work is
    // not, even when a burst temporarily exceeds the retention limit.
    this.database.run(`DELETE FROM sync_jobs WHERE id IN (
      SELECT id FROM sync_jobs
      WHERE status NOT IN ('queued', 'running')
      ORDER BY created_at DESC LIMIT -1 OFFSET ${maxJobs}
    )`);
    this.database.run(`DELETE FROM audit_events WHERE id IN (
      SELECT id FROM audit_events ORDER BY id DESC LIMIT -1 OFFSET ${maxAudit}
    )`);
    this.database.run(`DELETE FROM sync_snapshots WHERE id IN (
      SELECT id FROM sync_snapshots ORDER BY created_at DESC LIMIT -1 OFFSET ${maxSnapshots}
    )`);
    this.database.run(`DELETE FROM job_claims WHERE job_id NOT IN (
      SELECT id FROM sync_jobs WHERE status IN ('queued', 'running')
    )`);
  }

  async initialize() {
    ensureDirectoryTree(path.dirname(this.dbPath), 'SQLite 数据库目录');
    this.pinDatabaseDirectory();
    const SQL = await initSqlJs({
      locateFile: (file) => path.join(path.dirname(require.resolve('sql.js')), file),
    });
    this.SQL = SQL;
    await this.withFileLock(async () => {
      this.loadDatabaseFromDisk();
      this.runSchema();
      // The worker queue lives in the process that created the job. Preserve
      // jobs owned by another still-running panel instance; only a dead owner
      // proves that queued/running work was interrupted. This also prevents a
      // second PanelDb object in the same process from releasing live claims.
      const interruptedAt = new Date().toISOString();
      const activeJobs = resultRows(this.database.exec(`SELECT id, owner_pid, owner_start_id, owner_boot_id
        FROM sync_jobs WHERE status IN ('queued', 'running')`));
      const interrupted = activeJobs.filter((job) => (
        !storedJobOwnerIsAlive(job)
      ));
      if (interrupted.length > 0) {
        const statement = this.database.prepare(`UPDATE sync_jobs
          SET status = 'interrupted', error = ?, finished_at = ?
          WHERE id = ? AND status IN ('queued', 'running')`);
        try {
          for (const job of interrupted) {
            statement.run(['面板任务所属进程已退出，任务未恢复执行', interruptedAt, job.id]);
          }
        } finally {
          statement.free();
        }
      }
      this.database.run(`DELETE FROM job_claims WHERE job_id NOT IN (
        SELECT id FROM sync_jobs WHERE status IN ('queued', 'running')
      )`);
      this.pruneRows();
      this.persistUnlocked();
    });
  }

  async initializeLocalDatabase() {
    ensureDirectoryTree(path.dirname(this.dbPath), 'SQLite 数据库目录');
    this.pinDatabaseDirectory();
    this.SQL = await initSqlJs({
      locateFile: (file) => path.join(path.dirname(require.resolve('sql.js')), file),
    });
    this.loadDatabaseFromDisk();
    this.runSchema();
  }

  persistUnlocked() {
    const bytes = this.database.export();
    const maximumBytes = databaseMaximumBytes();
    if (bytes.byteLength > maximumBytes) {
      // Fail before opening a temporary output file. The last durable version
      // remains intact and the next operation will reload it from disk.
      const error = new Error('SQLite 数据库文件超过安全上限');
      error.code = 'PANEL_DB_TOO_LARGE';
      error.actualBytes = bytes.byteLength;
      error.maximumBytes = maximumBytes;
      throw error;
    }
    const pinnedDirectory = this.openPinnedDatabaseDirectory();
    const fileName = path.basename(this.dbPath);
    const temporaryPath = path.join(
      pinnedDirectory.accessDirectory,
      fileName + '.tmp-' + process.pid + '-' + crypto.randomBytes(4).toString('hex'),
    );
    const targetPath = path.join(pinnedDirectory.accessDirectory, fileName);
    let descriptor;
    try {
      descriptor = fs.openSync(
        temporaryPath,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | (fs.constants.O_NOFOLLOW || 0),
        0o600,
      );
      fs.writeFileSync(descriptor, Buffer.from(bytes));
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      fs.renameSync(temporaryPath, targetPath);
      fs.fsyncSync(pinnedDirectory.descriptor);
    } finally {
      if (descriptor !== undefined) {
        try { fs.closeSync(descriptor); } catch {}
      }
      try { fs.unlinkSync(temporaryPath); } catch {}
      try { fs.closeSync(pinnedDirectory.descriptor); } catch {}
    }
  }

  async persist() {
    // Compatibility entrypoint for older embedded callers. Never export this
    // instance's cached database directly: another PanelDb/process may have
    // committed newer rows since the last local read. A no-op write reloads
    // the current file under the lease before persisting schema/pruning work.
    await this.write(() => undefined);
  }

  async write(callback) {
    await this.ready;
    const run = this.queue.then(async () => {
      return this.withFileLock(async () => {
        this.loadDatabaseFromDisk();
        this.runSchema();
        const result = await callback(this.database);
        this.pruneRows();
        this.persistUnlocked();
        return result;
      });
    });
    this.queue = run.catch(() => {});
    return run;
  }

  async read(callback) {
    await this.ready;
    await this.queue;
    // Atomic rename makes this read safe while another process persists. A
    // fresh load also prevents a second PanelDb instance from serving stale
    // task state indefinitely. Corrupt or replaced database files must be
    // surfaced instead of silently serving an old in-memory copy.
    this.loadDatabaseFromDisk();
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

  createJob(type, payload = {}, requestedBy = 'local', options = {}) {
    const id = randomId('job');
    const now = new Date().toISOString();
    const claimKeys = [...new Set((Array.isArray(options.claimKeys) ? options.claimKeys : [])
      .map((key) => String(key || '').trim())
      .filter((key) => key && key.length <= 512))];
    const owner = currentProcessOwner();
    let safePayloadJson;
    try {
      safePayloadJson = boundedJsonString('sync_jobs.payload_json', payload, MAX_JOB_PAYLOAD_BYTES);
    } catch (error) {
      return Promise.reject(error);
    }
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        for (const claimKey of claimKeys) {
          let existing = resultRows(database.exec(
            'SELECT job_id FROM job_claims WHERE claim_key = ' + sqlString(claimKey) + ' LIMIT 1',
          ))[0];
          if (existing) {
            const owner = resultRows(database.exec(`SELECT id, status, owner_pid, owner_start_id, owner_boot_id
              FROM sync_jobs WHERE id = ${sqlString(existing.job_id)} LIMIT 1`))[0];
            const ownerIsActive = owner && ['queued', 'running'].includes(owner.status);
            if (!ownerIsActive || !storedJobOwnerIsAlive(owner)) {
              if (ownerIsActive) {
                const interrupted = database.prepare(`UPDATE sync_jobs
                  SET status = 'interrupted', error = ?, finished_at = ?
                  WHERE id = ? AND status IN ('queued', 'running')`);
                try {
                  interrupted.run([
                    '面板任务所属进程已退出，任务未恢复执行',
                    now,
                    existing.job_id,
                  ]);
                } finally {
                  interrupted.free();
                }
              }
              database.run(
                'DELETE FROM job_claims WHERE job_id = ' + sqlString(existing.job_id),
              );
              existing = null;
            }
          }
          if (existing) {
            const error = new Error('该操作目标已有任务排队或运行中');
            error.code = 'JOB_ALREADY_CLAIMED';
            error.existingJobId = existing.job_id;
            error.claimKey = claimKey;
            throw error;
          }
        }
        const statement = database.prepare(`INSERT INTO sync_jobs
          (id, type, status, requested_by, payload_json, created_at, claim_keys_json,
            owner_pid, owner_start_id, owner_boot_id)
          VALUES (?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?)`);
        statement.run([
          id,
          type,
          requestedBy,
          safePayloadJson,
          now,
          jsonString(claimKeys),
          owner.pid,
          owner.processStartId,
          owner.processBootId,
        ]);
        statement.free();
        if (claimKeys.length > 0) {
          const claimStatement = database.prepare(`INSERT INTO job_claims
            (claim_key, job_id, job_type, created_at) VALUES (?, ?, ?, ?)`);
          try {
            for (const claimKey of claimKeys) claimStatement.run([claimKey, id, type, now]);
          } finally {
            claimStatement.free();
          }
        }
        database.run('COMMIT');
        return { id, type, status: 'queued', requestedBy, createdAt: now };
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
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
    let safeResultJson;
    let safeError;
    try {
      safeResultJson = patch.result === undefined
        ? undefined
        : boundedJsonString('sync_jobs.result_json', patch.result, MAX_JOB_RESULT_BYTES);
      safeError = patch.error === undefined
        ? undefined
        : patch.error === null
          ? null
          : assertStoredByteLength(
            'sync_jobs.error',
            redactText(String(patch.error)),
            MAX_JOB_ERROR_BYTES,
          );
    } catch (error) {
      return Promise.reject(error);
    }
    add('status', patch.status);
    add('result_json', safeResultJson);
    add('error', safeError);
    add('started_at', patch.startedAt);
    add('finished_at', patch.finishedAt);
    if (fields.length === 0) return Promise.resolve();
    const hasRequestedStatus = patch.status !== undefined;
    const requestedStatus = hasRequestedStatus ? patch.status : null;
    if (hasRequestedStatus && !JOB_STATUSES.has(requestedStatus)) {
      const error = new Error('任务状态无效');
      error.code = 'JOB_STATUS_INVALID';
      return Promise.reject(error);
    }
    const terminalStatus = TERMINAL_JOB_STATUSES.has(requestedStatus)
      ? requestedStatus
      : null;
    return this.write((database) => {
      const row = resultRows(database.exec(
        'SELECT status FROM sync_jobs WHERE id = ' + sqlString(id) + ' LIMIT 1',
      ))[0];
      if (!row) {
        const error = new Error('任务不存在');
        error.code = 'JOB_NOT_FOUND';
        throw error;
      }
      const currentStatus = String(row.status || '');
      if (!JOB_STATUSES.has(currentStatus)) {
        const error = new Error('数据库中的任务状态无效');
        error.code = 'JOB_STORED_STATUS_INVALID';
        error.currentStatus = currentStatus || null;
        throw error;
      }
      if (TERMINAL_JOB_STATUSES.has(currentStatus)) {
        if (terminalStatus === currentStatus) {
          // A retry after an ambiguous local persistence response may replay
          // the same terminal state. Confirm it without replacing the first
          // terminal result, error, or timestamp.
          return {
            applied: false,
            idempotent: true,
            previousStatus: currentStatus,
            currentStatus,
          };
        }
        const error = new Error('任务已经结束，拒绝重新打开或覆盖终态');
        error.code = 'JOB_STATUS_CONFLICT';
        error.currentStatus = currentStatus;
        error.requestedStatus = requestedStatus;
        throw error;
      }
      const transitionAllowed = !hasRequestedStatus
        || (currentStatus === 'queued'
          && (requestedStatus === 'running' || terminalStatus !== null))
        || (currentStatus === 'running'
          && (requestedStatus === 'running' || terminalStatus !== null));
      if (!transitionAllowed) {
        const error = new Error('任务状态转换无效');
        error.code = 'JOB_STATUS_CONFLICT';
        error.currentStatus = currentStatus;
        error.requestedStatus = requestedStatus;
        throw error;
      }
      const statement = database.prepare(
        'UPDATE sync_jobs SET ' + fields.join(', ') + ' WHERE id = ? AND status = ?',
      );
      statement.run([...values, id, currentStatus]);
      const applied = database.getRowsModified() > 0;
      statement.free();
      if (!applied) {
        const latestStatus = resultRows(database.exec(
          'SELECT status FROM sync_jobs WHERE id = ' + sqlString(id) + ' LIMIT 1',
        ))[0]?.status || null;
        const error = new Error('任务状态在更新期间发生变化');
        error.code = latestStatus ? 'JOB_STATUS_CONFLICT' : 'JOB_NOT_FOUND';
        error.currentStatus = latestStatus;
        error.requestedStatus = requestedStatus;
        throw error;
      }
      if (terminalStatus && applied) {
        const claimStatement = database.prepare('DELETE FROM job_claims WHERE job_id = ?');
        claimStatement.run([id]);
        claimStatement.free();
      }
      return {
        applied: true,
        idempotent: false,
        previousStatus: currentStatus,
        currentStatus: hasRequestedStatus ? requestedStatus : currentStatus,
      };
    });
  }

  interruptOwnedActiveJobs(reason = '面板服务停止，任务已安全中断', options = {}) {
    const owner = currentProcessOwner();
    const finishedAt = new Date().toISOString();
    const safeReason = redactText(String(reason || '面板服务停止，任务已安全中断'));
    const excludedJobIds = new Set(
      (Array.isArray(options?.excludeJobIds) ? options.excludeJobIds : [])
        .map((id) => String(id || '').trim())
        .filter(Boolean),
    );
    return this.write((database) => {
      database.run('BEGIN IMMEDIATE');
      try {
        const startCondition = owner.processStartId
          ? 'owner_start_id = ' + sqlString(owner.processStartId)
          : 'owner_start_id IS NULL';
        const bootCondition = owner.processBootId
          ? 'owner_boot_id = ' + sqlString(owner.processBootId)
          : 'owner_boot_id IS NULL';
        const rows = resultRows(database.exec(`SELECT id FROM sync_jobs
          WHERE status IN ('queued', 'running')
            AND owner_pid = ${sqlString(owner.pid)}
            AND ${startCondition}
            AND ${bootCondition}`))
          .filter((row) => !excludedJobIds.has(String(row.id)));
        if (rows.length > 0) {
          const statement = database.prepare(`UPDATE sync_jobs
            SET status = 'interrupted', error = ?, finished_at = ?
            WHERE id = ? AND status IN ('queued', 'running')`);
          try {
            for (const row of rows) statement.run([safeReason, finishedAt, row.id]);
          } finally {
            statement.free();
          }
          const release = database.prepare('DELETE FROM job_claims WHERE job_id = ?');
          try {
            for (const row of rows) release.run([row.id]);
          } finally {
            release.free();
          }
        }
        database.run('COMMIT');
        return rows.map((row) => row.id);
      } catch (error) {
        try { database.run('ROLLBACK'); } catch {}
        throw error;
      }
    });
  }

  decodeJob(row) {
    if (!row) return null;
    let payload = null;
    let result = null;
    try { payload = redactValue(JSON.parse(row.payload_json)); } catch {}
    try { result = row.result_json ? redactValue(JSON.parse(row.result_json)) : null; } catch {}
    return {
      id: row.id,
      type: row.type,
      status: row.status,
      requestedBy: row.requested_by,
      payload,
      result,
      error: row.error ? redactText(String(row.error)) : null,
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

  async countActiveJobs(type = null) {
    const normalizedType = typeof type === 'string' ? type.trim() : '';
    const condition = normalizedType
      ? ' AND type = ' + sqlString(normalizedType)
      : '';
    const rows = await this.read((database) => resultRows(database.exec(
      `SELECT COUNT(*) AS count FROM sync_jobs
        WHERE status IN ('queued', 'running')${condition}`,
    )));
    const count = Number(rows[0]?.count);
    return Number.isSafeInteger(count) && count >= 0 ? count : 0;
  }

  audit(event = {}) {
    const now = new Date().toISOString();
    let values;
    try {
      values = [
        event.jobId || null,
        event.actor || 'local',
        event.action || 'unknown',
        event.targetKey || null,
        event.beforeFingerprint || null,
        event.afterFingerprint || null,
        event.result || 'ok',
      ];
      const fields = [
        'audit_events.job_id',
        'audit_events.actor',
        'audit_events.action',
        'audit_events.target_key',
        'audit_events.before_fingerprint',
        'audit_events.after_fingerprint',
        'audit_events.result',
      ];
      values = values.map((value, index) => (
        assertStoredByteLength(fields[index], value, MAX_AUDIT_TEXT_BYTES)
      ));
      values.push(boundedJsonString(
        'audit_events.details_json',
        event.details || {},
        MAX_AUDIT_DETAILS_BYTES,
      ));
    } catch (error) {
      return Promise.reject(error);
    }
    return this.write((database) => {
      const statement = database.prepare(`INSERT INTO audit_events
        (job_id, actor, action, target_key, before_fingerprint, after_fingerprint, result, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      statement.run([...values, now]);
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
      try { details = redactValue(JSON.parse(row.details_json || '{}')); } catch {}
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
        link.sub2apiId ?? null,
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
