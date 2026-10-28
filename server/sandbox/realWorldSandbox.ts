import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
import ts from 'typescript';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { INITIAL_REPO_FILES, TARGET_REPO_IS_FIXTURE, TARGET_REPO_ROOT } from '../analyzer/repoBaseline.js';
import { resolveSandboxPython } from '../util/python.js';
import { executeSchemaOnPostgres, type PostgresExecutionReport } from './postgresSandbox.js';

export interface RealWorldSandboxReport {
  executedAt: string;
  git: {
    branch: string;
    headCommit: string;
    commitLog: string[];
    gitDiffStat: string;
    workingTreeClean: boolean;
  };
  sqlDatabaseExecution: PostgresExecutionReport;
  pythonFastApiExecution: {
    runtimeVersion: string;
    frameworks: string;
    httpStatus: number | null;
    testPayload: Record<string, string>;
    capturedLoggerOutput: string;
    leakedPlaintextSsnInLogs: boolean;
    returnedResponse: Record<string, unknown>;
  };
  pythonRedisWorkerExecution: {
    capturedSetexKey: string;
    capturedSetexTtlSeconds: number;
    storedTtlSeconds: number;
    redisBackend: string;
    capturedSetexTtlHours: number;
    capturedSetexPayload: string;
    purgeWorkerStatus: Record<string, unknown>;
  };
  typescriptAiTriageExecution: {
    testInput: Record<string, unknown>;
    returnedDecision: Record<string, unknown>;
    violatedEuAiActArt14: boolean;
  };
  typescriptCrossBorderExecution: {
    returnedSyncStatus: Record<string, unknown>;
    violatedGdprArt44: boolean;
  };
}

const execFileAsync = promisify(execFile);

const TS_TEST_INPUT = {
  patientId: 'pat-9921',
  tenantId: 'tenant-zurich-01',
  diagnosisCode: 'ICD10-I21.0',
  requestedCreditLimit: 25000,
  modelConfidenceScore: 0.78,
};

/**
 * Transpiles the TypeScript services with the TypeScript compiler and executes them in a
 * separate Node process under the permission model (read access to the scratch copy
 * only; no child processes, workers, or writes).
 */
async function runTypeScriptServices(workDir: string, minAiConfidence: number, allowedRegions: string[]) {
  for (const rel of ['services/ai_credit_triage.ts', 'services/cross_border_sync.ts']) {
    const source = fs.readFileSync(path.join(workDir, rel), 'utf8');
    const { outputText } = ts.transpileModule(source, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
    });
    fs.writeFileSync(path.join(workDir, rel.replace(/\.ts$/, '.cjs')), outputText);
  }
  const runner = `
const pick = (mod, re) => Object.entries(mod).find(([k, v]) => typeof v === 'function' && re.test(k));
(async () => {
  const ai = pick(require('./services/ai_credit_triage.cjs'), /evaluat|triage|decision|risk/i);
  const cb = pick(require('./services/cross_border_sync.cjs'), /replicat|sync|transfer/i);
  const input = ${JSON.stringify(TS_TEST_INPUT)};
  const decision = ai ? await ai[1](input) : null;
  const sync = cb ? await cb[1]({ tenantId: input.tenantId, patientId: input.patientId, encryptedPayload: 'ciphertext' }) : null;
  process.stdout.write(JSON.stringify({ aiFn: ai && ai[0], cbFn: cb && cb[0], decision, sync }));
})().catch((err) => process.stdout.write(JSON.stringify({ error: String(err) })));
`;
  fs.writeFileSync(path.join(workDir, 'lexcompiler-ts-runner.cjs'), runner);
  const { stdout } = await execFileAsync(
    process.execPath,
    ['--permission', `--allow-fs-read=${workDir}`, '--max-old-space-size=128', 'lexcompiler-ts-runner.cjs'],
    { cwd: workDir, env: { PATH: process.env.PATH || '/usr/bin:/bin' }, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024 }
  );
  const result = JSON.parse(stdout) as {
    error?: string;
    aiFn?: string;
    cbFn?: string;
    decision?: { approved?: boolean; executionMode?: string; confidenceScore?: number; auditTrailRecorded?: boolean } | null;
    sync?: { destinationRegion?: string } | null;
  };
  if (result.error) throw new Error(`TypeScript service execution failed: ${result.error}`);
  const decision = result.decision || {};
  const region = result.sync?.destinationRegion || '';
  return {
    ai: {
      testInput: TS_TEST_INPUT as Record<string, unknown>,
      returnedDecision: { ...decision, executedFunction: result.aiFn } as Record<string, unknown>,
      violatedEuAiActArt14:
        (decision.executionMode === 'AUTONOMOUS_AI' && TS_TEST_INPUT.modelConfidenceScore < minAiConfidence) ||
        decision.auditTrailRecorded !== true,
    },
    crossBorder: {
      returnedSyncStatus: { ...(result.sync || {}), executedFunction: result.cbFn } as Record<string, unknown>,
      violatedGdprArt44: !allowedRegions.includes(region),
    },
  };
}

/** Separate Git dir tracking the demo fixture's history (never the user's own `.git`). */
const SANDBOX_GIT_DIR = path.resolve(process.env.LEXCOMPILER_SANDBOX_GIT_DIR || path.join(process.cwd(), 'data', 'sandbox-git'));

function runGit(args: string[]): string {
  try {
    return execFileSync('git', args, {
      cwd: TARGET_REPO_ROOT,
      env: {
        ...process.env,
        GIT_DIR: SANDBOX_GIT_DIR,
        GIT_WORK_TREE: TARGET_REPO_ROOT,
      },
      encoding: 'utf8',
      timeout: 4000,
    }).trim();
  } catch {
    return '';
  }
}

export function ensureTargetRepoGitInitialized(): void {
  if (!TARGET_REPO_IS_FIXTURE) return;
  const legacyNestedGit = path.join(TARGET_REPO_ROOT, '.git');
  if (fs.existsSync(legacyNestedGit)) {
    fs.rmSync(legacyNestedGit, { recursive: true, force: true });
  }
  if (!fs.existsSync(SANDBOX_GIT_DIR)) {
    fs.mkdirSync(path.dirname(SANDBOX_GIT_DIR), { recursive: true });
    runGit(['init']);
    runGit(['checkout', '-B', 'main']);
    runGit(['config', 'user.name', 'LexCompiler Autonomous Enforcer']);
    runGit(['config', 'user.email', 'lexcompiler-bot@justicesphere.ai']);
    runGit(['add', '.']);
    runGit(['commit', '-m', 'feat(baseline): initial FinHealth AI polyglot repository (30d TTL)']);
  }
}

export function commitTargetRepoChanges(commitMessage: string): string {
  if (!TARGET_REPO_IS_FIXTURE) return '';
  ensureTargetRepoGitInitialized();
  runGit(['add', '.']);
  const status = runGit(['status', '--porcelain']);
  if (status) {
    runGit(['commit', '-m', commitMessage]);
  }
  return runGit(['rev-parse', '--short', 'HEAD']) || 'HEAD';
}

export function resetTargetRepoGitHistory(): void {
  if (!TARGET_REPO_IS_FIXTURE) return;
  const legacyNestedGit = path.join(TARGET_REPO_ROOT, '.git');
  if (fs.existsSync(legacyNestedGit)) {
    fs.rmSync(legacyNestedGit, { recursive: true, force: true });
  }
  if (fs.existsSync(SANDBOX_GIT_DIR)) {
    fs.rmSync(SANDBOX_GIT_DIR, { recursive: true, force: true });
  }
  ensureTargetRepoGitInitialized();
}

/**
 * Executes the actual target-repo SQL DDL, Python 3 endpoints/workers, and TypeScript services
 * in a real local sandbox environment and returns the concrete runtime outputs.
 */
export async function executeRealWorldSandboxVerification(
  policy: { minAiConfidence?: number; allowedRegions?: string[] } = {}
): Promise<RealWorldSandboxReport> {
  if (!TARGET_REPO_IS_FIXTURE) {
    throw new Error('The runtime sandbox only supports the bundled demo fixture, not LEXCOMPILER_TARGET_REPO repositories.');
  }
  ensureTargetRepoGitInitialized();

  const branch = runGit(['rev-parse', '--abbrev-ref', 'HEAD']) || 'main';
  const headCommit = runGit(['rev-parse', '--short', 'HEAD']) || 'initial';
  const logRaw = runGit(['log', '--oneline', '-n', '5']);
  const commitLog = logRaw ? logRaw.split('\n') : [];
  const gitDiffStat = runGit(['show', '--stat', '--oneline', 'HEAD']);
  const workingTreeClean = runGit(['status', '--porcelain']) === '';

  const pyRunnerScript = `
import sys

# Defense in depth only: these limits are not an isolation boundary.
if sys.platform == "win32":
    # No rlimits on Windows: put this process in a Job Object with the same CPU (5 s),
    # memory (512 MiB) and no-child-process limits. Windows has no per-file size cap.
    import ctypes
    from ctypes import wintypes

    class _BasicLimits(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(_n, ctypes.c_uint64) for _n in ("ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _BasicLimits),
            ("IoInfo", _IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    _JOB_OBJECT_LIMIT_PROCESS_TIME = 0x2
    _JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x8
    _JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x100
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
    _JobObjectExtendedLimitInformation = 9
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    _kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    _kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    _kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    _limits = _ExtendedLimits()
    _limits.BasicLimitInformation.LimitFlags = (
        _JOB_OBJECT_LIMIT_PROCESS_TIME
        | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | _JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    )
    _limits.BasicLimitInformation.PerProcessUserTimeLimit = 5 * 10_000_000
    _limits.BasicLimitInformation.ActiveProcessLimit = 1
    _limits.ProcessMemoryLimit = 512 * 1024 * 1024
    _job = _kernel32.CreateJobObjectW(None, None)
    if _job:
        _kernel32.SetInformationJobObject(_job, _JobObjectExtendedLimitInformation, ctypes.byref(_limits), ctypes.sizeof(_limits))
        _kernel32.AssignProcessToJobObject(_job, _kernel32.GetCurrentProcess())
else:
    import resource

    for _limit, _value in (
        (resource.RLIMIT_CPU, 5),
        (resource.RLIMIT_AS, 512 * 1024 * 1024),
        (resource.RLIMIT_FSIZE, 1024 * 1024),
        (resource.RLIMIT_NPROC, 0),
    ):
        try:
            resource.setrlimit(_limit, (_value, _value))
        except (ValueError, OSError):
            pass

import json, sys, re, io, logging, asyncio, types, os

repo_root = sys.argv[1]

# 2. Execute Python FastAPI Intake Module (api/fastapi_intake.py)
# Real FastAPI/Pydantic when installed (npm run setup:sandbox); minimal shims otherwise.
try:
    import fastapi, pydantic
    import httpx
    real_frameworks = True
    frameworks = f"FastAPI {fastapi.__version__} + Pydantic {pydantic.VERSION} (HTTP via httpx ASGI transport)"
except ImportError:
    real_frameworks = False
    frameworks = "shimmed FastAPI/Pydantic (run npm run setup:sandbox for the real packages)"
    fa_mod = types.ModuleType("fastapi")
    class DummyFastAPI:
        def __init__(self, **kwargs): pass
        def post(self, path):
            def dec(fn): return fn
            return dec
    fa_mod.FastAPI = DummyFastAPI
    fa_mod.Header = lambda default=None: default
    fa_mod.HTTPException = Exception
    sys.modules["fastapi"] = fa_mod
    pyd_mod = types.ModuleType("pydantic")
    class DummyBaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    pyd_mod.BaseModel = DummyBaseModel
    sys.modules["pydantic"] = pyd_mod

log_stream = io.StringIO()
handler = logging.StreamHandler(log_stream)
handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
intake_logger = logging.getLogger("finhealth.intake")
intake_logger.setLevel(logging.INFO)
intake_logger.handlers = [handler]
intake_logger.propagate = False

with open(f"{repo_root}/api/fastapi_intake.py", "r", encoding="utf-8") as f:
    intake_code = f.read()

intake_ns = {}
exec(compile(intake_code, f"{repo_root}/api/fastapi_intake.py", "exec"), intake_ns)

class SandboxKmsClient:
    """Test double for the KMS client that remediated code requires (encrypt only, no key material)."""
    def encrypt(self, tenant_id, plaintext):
        import hashlib
        return f"kms:{tenant_id}:".encode("utf-8") + hashlib.sha256(plaintext).digest()

if "TENANT_KMS_CLIENT" in intake_ns:
    intake_ns["TENANT_KMS_CLIENT"] = SandboxKmsClient()

payload_dict = dict(
    tenant_id="tenant-zurich-01",
    patient_id="pat-9921",
    full_name="Dr. Elena Rostova",
    email="elena.rostova@zurich-clinic.ch",
    ssn="999-42-8810",
    diagnosis_code="ICD10-I21.0"
)

if real_frameworks:
    # A real HTTP request through FastAPI routing, Pydantic validation and header binding
    # (in-process ASGI transport: no sockets, no threads).
    async def _post():
        transport = httpx.ASGITransport(app=intake_ns["app"])
        async with httpx.AsyncClient(transport=transport, base_url="http://sandbox") as client:
            return await client.post("/api/v1/patients/intake", json=payload_dict, headers={"x-tenant-id": "tenant-zurich-01"})
    http = asyncio.run(_post())
    intake_response = http.json()
    http_status = http.status_code
else:
    payload_obj = intake_ns["PatientIntakePayload"](**payload_dict)
    intake_response = asyncio.run(intake_ns["ingest_patient_pii"](payload_obj, x_tenant_id="tenant-zurich-01"))
    http_status = None
captured_log = log_stream.getvalue().strip()
leaked_ssn = ("999-42-8810" in captured_log) or ("elena.rostova@zurich-clinic.ch" in captured_log)

# 3. Execute Python Redis Cache & Purge Worker (workers/redis_cache_worker.py)
with open(f"{repo_root}/workers/redis_cache_worker.py", "r", encoding="utf-8") as f:
    redis_code = f.read()

redis_ns = {}
exec(compile(redis_code, f"{repo_root}/workers/redis_cache_worker.py", "exec"), redis_ns)

class RecordingRedis:
    """Wraps a Redis client and records the last SETEX call."""
    def __init__(self, inner):
        self.inner = inner
        self.last_key = ""
        self.last_ttl = 0
        self.last_val = ""
    def setex(self, k, ttl, val):
        self.last_key, self.last_ttl, self.last_val = k, int(ttl), val
        return self.inner.setex(k, ttl, val) if self.inner is not None else True
    def __getattr__(self, name):
        return getattr(self.inner, name)

redis_url = os.environ.get("LEXCOMPILER_REDIS_URL")
try:
    if redis_url:
        import redis as redis_lib
        inner_redis = redis_lib.Redis.from_url(redis_url)
        redis_backend = f"Redis server ({redis_url.split('@')[-1]})"
    else:
        import fakeredis
        inner_redis = fakeredis.FakeRedis()
        redis_backend = f"fakeredis {fakeredis.__version__} (Redis command semantics in-process)"
except ImportError:
    inner_redis = None
    redis_backend = "recording stub (run npm run setup:sandbox for fakeredis)"

mock_redis = RecordingRedis(inner_redis)
worker = redis_ns["RedisSessionCacheWorker"](mock_redis)
worker.cache_patient_session("tenant-zurich-01", "pat-9921", {"ssn_token": "999-42-8810", "diagnosis": "ICD10-I21.0"})
purge_status = worker.enforce_retention_purge()
# TTL as stored by the Redis engine itself, not just the argument passed to SETEX.
stored_ttl = int(inner_redis.ttl(mock_redis.last_key)) if inner_redis is not None else mock_redis.last_ttl
if inner_redis is not None and redis_url:
    inner_redis.delete(mock_redis.last_key)

print(json.dumps({
    "fastapi": {
        "runtimeVersion": f"Python {sys.version.split()[0]}",
        "frameworks": frameworks,
        "httpStatus": http_status,
        "testPayload": {
            "tenant_id": "tenant-zurich-01",
            "patient_id": "pat-9921",
            "email": "elena.rostova@zurich-clinic.ch",
            "ssn": "999-42-8810",
            "diagnosis_code": "ICD10-I21.0"
        },
        "capturedLoggerOutput": captured_log,
        "leakedPlaintextSsnInLogs": leaked_ssn,
        "returnedResponse": intake_response
    },
    "redis": {
        "capturedSetexKey": mock_redis.last_key,
        "capturedSetexTtlSeconds": mock_redis.last_ttl,
        "storedTtlSeconds": stored_ttl,
        "redisBackend": redis_backend,
        "capturedSetexTtlHours": int(mock_redis.last_ttl // 3600),
        "capturedSetexPayload": mock_redis.last_val,
        "purgeWorkerStatus": purge_status
    }
}))
`;

  // Run against a throwaway copy of the tracked files, with an isolated interpreter
  // (-I: no user site-packages, no PYTHON* env vars) and an empty environment.
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lexcompiler-sandbox-'));
  let stdout: string;
  let tsRun!: Awaited<ReturnType<typeof runTypeScriptServices>>;
  let sqlRun!: PostgresExecutionReport;
  try {
    for (const relPath of Object.keys(INITIAL_REPO_FILES)) {
      const dest = path.join(workDir, relPath);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.copyFileSync(path.join(TARGET_REPO_ROOT, relPath), dest);
    }
    const python = resolveSandboxPython();
    if (!python) throw new Error('No Python >= 3.10 interpreter found (tried LEXCOMPILER_PYTHON, python3, python, py -3)');
    const { stdout: out } = await execFileAsync(python.command, [...python.prefixArgs, '-I', '-c', pyRunnerScript, workDir], {
      cwd: workDir,
      // Windows needs SYSTEMROOT for the interpreter's crypto/random init.
      env: {
        PATH: process.env.PATH || '/usr/bin:/bin',
        LANG: 'C.UTF-8',
        ...(process.env.LEXCOMPILER_REDIS_URL ? { LEXCOMPILER_REDIS_URL: process.env.LEXCOMPILER_REDIS_URL } : {}),
        ...(process.platform === 'win32' && process.env.SYSTEMROOT ? { SYSTEMROOT: process.env.SYSTEMROOT } : {}),
      },
      windowsHide: true,
      encoding: 'utf8',
      timeout: 15000,
      maxBuffer: 2 * 1024 * 1024,
    });
    stdout = out;
    sqlRun = await executeSchemaOnPostgres(fs.readFileSync(path.join(workDir, 'schema/postgres_pii.sql'), 'utf8'));
    tsRun = await runTypeScriptServices(workDir, policy.minAiConfidence ?? 0.85, policy.allowedRegions ?? ['eu-central-1', 'eu-west-1']);
  } finally {
    fs.rmSync(workDir, { recursive: true, force: true });
  }
  const parsed = JSON.parse(stdout);

  return {
    executedAt: new Date().toISOString(),
    git: {
      branch,
      headCommit,
      commitLog,
      gitDiffStat,
      workingTreeClean,
    },
    sqlDatabaseExecution: sqlRun,
    pythonFastApiExecution: parsed.fastapi,
    pythonRedisWorkerExecution: parsed.redis,
    typescriptAiTriageExecution: tsRun.ai,
    typescriptCrossBorderExecution: tsRun.crossBorder,
  };
}

export interface RepositoryIdentity {
  name: string;
  branch: string;
  commitHash: string;
  remoteUrl?: string;
  dirty: boolean;
}

/**
 * Identifies the scanned repository from Git (read-only): the sandbox history for the
 * demo fixture, or the repository's own `.git` otherwise. Falls back to a content hash
 * (prefixed `content-`) when the directory is not a Git checkout.
 */
export function resolveRepositoryIdentity(contentFingerprint: string): RepositoryIdentity {
  const git = (args: string[]): string => {
    if (TARGET_REPO_IS_FIXTURE) return runGit(args);
    try {
      const env = { ...process.env };
      delete env.GIT_DIR;
      delete env.GIT_WORK_TREE;
      return execFileSync('git', ['-C', TARGET_REPO_ROOT, ...args], { encoding: 'utf8', timeout: 4000, env, stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    } catch {
      return '';
    }
  };
  if (TARGET_REPO_IS_FIXTURE) ensureTargetRepoGitInitialized();
  const commit = git(['rev-parse', '--short=12', 'HEAD']);
  const remoteUrl = TARGET_REPO_IS_FIXTURE ? undefined : git(['remote', 'get-url', 'origin']) || undefined;
  const remoteName = remoteUrl?.match(/[:/]([^/:]+\/[^/]+?)(?:\.git)?$/)?.[1];
  return {
    name: TARGET_REPO_IS_FIXTURE ? 'finhealth-ai/core-platform' : remoteName || path.basename(TARGET_REPO_ROOT),
    branch: git(['rev-parse', '--abbrev-ref', 'HEAD']) || 'unknown',
    commitHash: commit || `content-${contentFingerprint.slice(0, 12)}`,
    remoteUrl,
    dirty: commit ? git(['status', '--porcelain']) !== '' : false,
  };
}
