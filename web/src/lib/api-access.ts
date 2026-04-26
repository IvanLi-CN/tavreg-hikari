import type { IntegrationApiKeyMutationPayload } from "@/lib/app-types";

export interface FinalizeIntegrationApiKeyMutationInput {
  mode: "create" | "rotate";
  payload: IntegrationApiKeyMutationPayload;
  refresh: () => Promise<void>;
}

export interface FinalizeIntegrationApiKeyMutationResult {
  revealedSecret:
    | {
        mode: "create" | "rotate";
        record: IntegrationApiKeyMutationPayload["record"];
        plainTextKey: string;
      }
    | null;
  refreshError: Error | null;
}

export interface ExecuteIntegrationApiKeyMutationInput {
  mode: "create" | "rotate";
  mutate: () => Promise<IntegrationApiKeyMutationPayload>;
  refresh: () => Promise<void>;
}

export interface ExecuteIntegrationApiKeyMutationResult extends FinalizeIntegrationApiKeyMutationResult {
  mutationError: Error | null;
  shouldCloseEditor: boolean;
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

export async function finalizeIntegrationApiKeyMutation(
  input: FinalizeIntegrationApiKeyMutationInput,
): Promise<FinalizeIntegrationApiKeyMutationResult> {
  const revealedSecret = input.payload.plainTextKey
    ? {
        mode: input.mode,
        record: input.payload.record,
        plainTextKey: input.payload.plainTextKey,
      }
    : null;
  try {
    await input.refresh();
    return {
      revealedSecret,
      refreshError: null,
    };
  } catch (error) {
    return {
      revealedSecret,
      refreshError: toError(error),
    };
  }
}

export async function executeIntegrationApiKeyMutation(
  input: ExecuteIntegrationApiKeyMutationInput,
): Promise<ExecuteIntegrationApiKeyMutationResult> {
  try {
    const payload = await input.mutate();
    const finalized = await finalizeIntegrationApiKeyMutation({
      mode: input.mode,
      payload,
      refresh: input.refresh,
    });
    return {
      ...finalized,
      mutationError: null,
      shouldCloseEditor: true,
    };
  } catch (error) {
    return {
      revealedSecret: null,
      refreshError: null,
      mutationError: toError(error),
      shouldCloseEditor: false,
    };
  }
}
