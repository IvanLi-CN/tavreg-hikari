import type { JobAttemptRecord, ProxyNodeRecord } from "../storage/app-db.js";

type AttemptProxySnapshot = Pick<JobAttemptRecord, "proxyNode" | "proxyIp">;

export interface ProxyNodeAllocationPolicy {
  allowNode?: (node: ProxyNodeRecord) => boolean;
  healthyStatuses?: string[];
}

export interface ProxyNodeAllocationInput {
  nodes: ProxyNodeRecord[];
  activeAttempts?: AttemptProxySnapshot[];
  blockedNodeNames?: string[];
  blockedEgressIps?: string[];
  policy?: ProxyNodeAllocationPolicy;
}

function normalizeStatus(status: string | null | undefined): string {
  return String(status || "").trim().toLowerCase();
}

function normalizeIp(ip: string | null | undefined): string {
  return String(ip || "").trim();
}

function byLeaseThenName(left: ProxyNodeRecord, right: ProxyNodeRecord): number {
  const leftLease = left.lastLeasedAt ? Date.parse(left.lastLeasedAt) : Number.NEGATIVE_INFINITY;
  const rightLease = right.lastLeasedAt ? Date.parse(right.lastLeasedAt) : Number.NEGATIVE_INFINITY;
  if (leftLease !== rightLease) {
    return leftLease - rightLease;
  }
  const leftChecked = left.lastCheckedAt ? Date.parse(left.lastCheckedAt) : Number.POSITIVE_INFINITY;
  const rightChecked = right.lastCheckedAt ? Date.parse(right.lastCheckedAt) : Number.POSITIVE_INFINITY;
  if (leftChecked !== rightChecked) {
    return leftChecked - rightChecked;
  }
  return left.nodeName.localeCompare(right.nodeName, "zh-Hans-CN");
}

function collectActiveProxyState(nodes: ProxyNodeRecord[], attempts: AttemptProxySnapshot[]) {
  const nodesByName = new Map(nodes.map((node) => [node.nodeName, node]));
  const activeNodeNames = new Set<string>();
  const activeIps = new Set<string>();
  for (const attempt of attempts) {
    const proxyNode = String(attempt.proxyNode || "").trim();
    if (proxyNode) {
      activeNodeNames.add(proxyNode);
    }
    const directIp = normalizeIp(attempt.proxyIp);
    if (directIp) {
      activeIps.add(directIp);
      continue;
    }
    const snapshotIp = normalizeIp(nodesByName.get(proxyNode)?.lastEgressIp);
    if (snapshotIp) {
      activeIps.add(snapshotIp);
    }
  }
  return { activeNodeNames, activeIps };
}

function chooseCandidate(
  nodes: ProxyNodeRecord[],
  input: {
    excludedNodeNames?: Set<string>;
    excludedIps?: Set<string>;
  },
): ProxyNodeRecord | null {
  for (const node of nodes) {
    if (input.excludedNodeNames?.has(node.nodeName)) continue;
    const ip = normalizeIp(node.lastEgressIp);
    if (ip && input.excludedIps?.has(ip)) continue;
    return node;
  }
  return null;
}

export function pickAutoProxyNode(input: ProxyNodeAllocationInput): ProxyNodeRecord | null {
  const allowNode = input.policy?.allowNode || (() => true);
  const healthyStatuses = new Set((input.policy?.healthyStatuses || ["ok", "succeeded", "running"]).map((status) => normalizeStatus(status)));
  const blockedNodeNames = new Set((input.blockedNodeNames || []).map((name) => String(name || "").trim()).filter(Boolean));
  const blockedEgressIps = new Set((input.blockedEgressIps || []).map(normalizeIp).filter(Boolean));

  const candidates = input.nodes
    .filter((node) => !blockedNodeNames.has(node.nodeName))
    .filter((node) => allowNode(node));

  if (candidates.length === 0) {
    return null;
  }

  const { activeNodeNames, activeIps } = collectActiveProxyState(candidates, input.activeAttempts || []);
  const distinctBlockedIps = new Set([...blockedEgressIps, ...activeIps]);
  const sorted = [...candidates].sort(byLeaseThenName);
  const healthy = sorted.filter((node) => healthyStatuses.has(normalizeStatus(node.lastStatus)));
  const untested = sorted.filter((node) => normalizeStatus(node.lastStatus) === "");
  const pools = [healthy, untested].filter((pool) => pool.length > 0);
  const stages = [
    (pool: ProxyNodeRecord[]) => chooseCandidate(pool, { excludedNodeNames: activeNodeNames, excludedIps: distinctBlockedIps }),
    (pool: ProxyNodeRecord[]) => chooseCandidate(pool, { excludedIps: distinctBlockedIps }),
    (pool: ProxyNodeRecord[]) => chooseCandidate(pool, { excludedNodeNames: activeNodeNames }),
    (pool: ProxyNodeRecord[]) => pool[0] || null,
  ];

  for (const stage of stages) {
    for (const pool of pools) {
      const candidate = stage(pool);
      if (candidate) return candidate;
    }
  }

  return null;
}
