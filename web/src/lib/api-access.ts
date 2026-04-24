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
