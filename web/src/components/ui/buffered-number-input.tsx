import { forwardRef, useEffect, useImperativeHandle, useState } from "react";
import { Input } from "@/components/ui/input";

export type BufferedNumberInputHandle = {
  commit: () => number;
};

type BufferedNumberInputProps = Omit<
  React.ComponentProps<typeof Input>,
  "defaultValue" | "inputMode" | "onChange" | "type" | "value"
> & {
  value: number;
  min: number;
  onCommit: (value: number) => void;
};

const DIGITS_ONLY = /^\d*$/;

export const BufferedNumberInput = forwardRef<BufferedNumberInputHandle, BufferedNumberInputProps>(function BufferedNumberInput(
  { disabled, min, onBlur, onCommit, onFocus, value, ...props },
  ref,
) {
  const [draft, setDraft] = useState(() => String(value));
  const [isFocused, setIsFocused] = useState(false);

  useEffect(() => {
    if (!isFocused) {
      setDraft(String(value));
    }
  }, [isFocused, value]);

  const commit = () => {
    const trimmed = draft.trim();
    if (trimmed === "") {
      setDraft(String(value));
      return value;
    }

    const parsed = Number.parseInt(trimmed, 10);
    if (!Number.isFinite(parsed)) {
      setDraft(String(value));
      return value;
    }

    const normalized = Math.max(min, Math.trunc(parsed));
    if (normalized !== value) {
      onCommit(normalized);
    }
    setDraft(String(normalized));
    return normalized;
  };

  useImperativeHandle(ref, () => ({ commit }), [draft, min, onCommit, value]);

  return (
    <Input
      {...props}
      disabled={disabled}
      inputMode="numeric"
      pattern="[0-9]*"
      type="text"
      value={draft}
      onBlur={(event) => {
        setIsFocused(false);
        commit();
        onBlur?.(event);
      }}
      onChange={(event) => {
        const nextValue = event.target.value;
        if (DIGITS_ONLY.test(nextValue)) {
          setDraft(nextValue);
        }
      }}
      onFocus={(event) => {
        setIsFocused(true);
        onFocus?.(event);
      }}
    />
  );
});
