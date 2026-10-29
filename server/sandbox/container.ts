/**
 * Optional container isolation for the runtime sandbox (LEXCOMPILER_SANDBOX_CONTAINER=docker|podman).
 * The scratch copy is mounted read-only at /work; the container has no network, a read-only
 * root filesystem, no capabilities, no privilege escalation, pid/memory/CPU limits, and runs as
 * nobody. LEXCOMPILER_SANDBOX_OCI_RUNTIME=runsc adds gVisor's user-space kernel.
 */
export interface ContainerSandbox {
  engine: string;
  image: string;
  ociRuntime?: string;
}

export const CONTAINER_WORKDIR = '/work';

export function containerSandboxFromEnv(env: NodeJS.ProcessEnv = process.env): ContainerSandbox | null {
  const engine = env.LEXCOMPILER_SANDBOX_CONTAINER?.trim();
  if (!engine) return null;
  return { engine, image: env.LEXCOMPILER_SANDBOX_IMAGE || 'lexcompiler-sandbox:1', ociRuntime: env.LEXCOMPILER_SANDBOX_OCI_RUNTIME || undefined };
}

export function containerRunArgs(c: ContainerSandbox, hostWorkDir: string, command: string[], limits = { memoryMb: 512, cpus: 1, pids: 64 }): string[] {
  return [
    'run',
    '--rm',
    '--network', 'none',
    '--read-only',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',
    '--cap-drop', 'ALL',
    '--security-opt', 'no-new-privileges',
    '--pids-limit', String(limits.pids),
    '--memory', `${limits.memoryMb}m`,
    '--cpus', String(limits.cpus),
    '--user', '65534:65534',
    '-v', `${hostWorkDir}:${CONTAINER_WORKDIR}:ro`,
    '-w', CONTAINER_WORKDIR,
    ...(c.ociRuntime ? ['--runtime', c.ociRuntime] : []),
    c.image,
    ...command,
  ];
}

export function describeIsolation(c: ContainerSandbox | null): string {
  return c ? `container (${c.engine}${c.ociRuntime ? `, ${c.ociRuntime}` : ''}; no network, read-only, no capabilities)` : 'local process (resource limits only; not an isolation boundary)';
}
