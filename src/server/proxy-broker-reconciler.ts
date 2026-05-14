import type { AppSettings } from "../storage/app-db.js";
import type { ProxyBrokerSession } from "../proxy/broker.js";
import { createProxyBrokerClient } from "./proxy-broker-runtime.js";

export interface BrokerSessionReference {
  sessionId: string;
  attemptId?: number | null;
  jobId?: number | null;
  jobStatus?: string | null;
  attemptStatus?: string | null;
  site?: string | null;
  startedAt?: string | null;
}

export interface BrokerSessionReconcileInput {
  sessions: ProxyBrokerSession[];
  references: BrokerSessionReference[];
}

export interface BrokerSessionReconcilePlan {
  activeSessionIds: string[];
  referencedSessionIds: string[];
  orphanSessions: ProxyBrokerSession[];
}

export interface BrokerSessionReconcileResult extends BrokerSessionReconcilePlan {
  apply: boolean;
  closedSessionIds: string[];
  skippedReferencedSessionIds: string[];
  closeErrors: Array<{ sessionId: string; message: string }>;
}

export function planProxyBrokerSessionReconciliation(input: BrokerSessionReconcileInput): BrokerSessionReconcilePlan {
  const referenced = new Set(
    input.references
      .map((item) => String(item.sessionId || "").trim())
      .filter(Boolean),
  );
  const activeSessionIds = input.sessions
    .map((session) => String(session.session_id || "").trim())
    .filter(Boolean);
  const orphanSessions = input.sessions.filter((session) => {
    const sessionId = String(session.session_id || "").trim();
    return Boolean(sessionId) && !referenced.has(sessionId);
  });
  return {
    activeSessionIds,
    referencedSessionIds: Array.from(referenced).sort(),
    orphanSessions,
  };
}

export async function reconcileProxyBrokerSessions(input: {
  settings: Pick<AppSettings, "proxyBrokerBaseUrl" | "proxyBrokerProfileId" | "timeoutMs">;
  references: BrokerSessionReference[];
  apply?: boolean;
  listSessions?: () => Promise<{ sessions: ProxyBrokerSession[] }>;
  closeSession?: (sessionId: string) => Promise<void>;
  refreshReferences?: () => BrokerSessionReference[] | Promise<BrokerSessionReference[]>;
  shouldSkipClose?: (sessionId: string) => boolean | Promise<boolean>;
}): Promise<BrokerSessionReconcileResult> {
  const client = input.listSessions && input.closeSession ? null : createProxyBrokerClient(input.settings);
  const listed = input.listSessions ? await input.listSessions() : await client!.listSessions();
  const plan = planProxyBrokerSessionReconciliation({
    sessions: listed.sessions,
    references: input.references,
  });
  const apply = Boolean(input.apply);
  const closedSessionIds: string[] = [];
  const skippedReferencedSessionIds: string[] = [];
  const closeErrors: Array<{ sessionId: string; message: string }> = [];
  if (apply) {
    for (const session of plan.orphanSessions) {
      const sessionId = String(session.session_id || "").trim();
      if (!sessionId) continue;
      if (input.refreshReferences) {
        const refreshedReferences = await input.refreshReferences();
        const refreshedReferenced = new Set(
          refreshedReferences
            .map((item) => String(item.sessionId || "").trim())
            .filter(Boolean),
        );
        if (refreshedReferenced.has(sessionId)) {
          skippedReferencedSessionIds.push(sessionId);
          continue;
        }
      }
      if (input.shouldSkipClose && await input.shouldSkipClose(sessionId)) {
        skippedReferencedSessionIds.push(sessionId);
        continue;
      }
      try {
        if (input.closeSession) {
          await input.closeSession(sessionId);
        } else {
          await client!.closeSession(sessionId);
        }
        closedSessionIds.push(sessionId);
      } catch (error) {
        closeErrors.push({
          sessionId,
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }
  return {
    ...plan,
    apply,
    closedSessionIds,
    skippedReferencedSessionIds,
    closeErrors,
  };
}
