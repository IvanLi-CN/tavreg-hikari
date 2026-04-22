import {
  FloatingArrow,
  FloatingPortal,
  autoUpdate,
  arrow,
  flip,
  offset,
  shift,
  useDismiss,
  useFloating,
  useInteractions,
  useRole,
} from "@floating-ui/react";
import { Check, Copy } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export type CopyButtonStatus = "idle" | "copied" | "failed";

function selectCopyContent(event: React.MouseEvent<HTMLElement> | React.FocusEvent<HTMLElement>) {
  const selection = window.getSelection();
  if (!selection) return;
  const range = document.createRange();
  range.selectNodeContents(event.currentTarget);
  selection.removeAllRanges();
  selection.addRange(range);
}

function toPlacement(
  side: "top" | "right" | "bottom" | "left",
  align: "start" | "center" | "end",
): "top" | "top-start" | "top-end" | "right" | "right-start" | "right-end" | "bottom" | "bottom-start" | "bottom-end" | "left" | "left-start" | "left-end" {
  if (align === "center") return side;
  return `${side}-${align}` as const;
}

export function CopyIconButton(props: {
  label: string;
  copyStatus: CopyButtonStatus;
  disabled?: boolean;
  onCopy: (anchorElement: HTMLElement) => void;
  size?: "default" | "compact" | "dense";
  idleIcon?: ReactNode;
  className?: string;
  feedbackContentClassName?: string;
  feedbackValue?: string;
  feedbackSubject?: string;
  successMessage?: string;
  failureMessage?: string;
  autoDismissMs?: number | null;
  forceFeedbackOpen?: boolean;
  feedbackEnabled?: boolean;
  feedbackSide?: "top" | "right" | "bottom" | "left";
  feedbackAlign?: "start" | "center" | "end";
  feedbackSideOffset?: number;
  feedbackAvoidCollisions?: boolean;
  feedbackPortalContainer?: HTMLElement | null;
}) {
  const feedbackEnabled = props.feedbackEnabled ?? true;
  const shouldOpenFeedback = feedbackEnabled && (props.forceFeedbackOpen || props.copyStatus !== "idle");
  const [feedbackOpen, setFeedbackOpen] = useState(() => shouldOpenFeedback);
  const feedbackTimerRef = useRef<number | null>(null);
  const arrowRef = useRef<SVGSVGElement | null>(null);
  const feedbackSide = props.feedbackSide ?? "right";
  const feedbackAlign = props.feedbackAlign ?? "center";
  const placement = useMemo(() => toPlacement(feedbackSide, feedbackAlign), [feedbackAlign, feedbackSide]);

  const { refs, floatingStyles, context } = useFloating({
    open: feedbackEnabled && feedbackOpen,
    onOpenChange: (open) => {
      if (!props.forceFeedbackOpen) {
        setFeedbackOpen(open);
      }
    },
    placement,
    strategy: props.feedbackPortalContainer ? "absolute" : "fixed",
    whileElementsMounted: autoUpdate,
    middleware: [
      offset(props.feedbackSideOffset ?? 8),
      ...(props.feedbackAvoidCollisions ?? true ? [flip({ padding: 12 }), shift({ padding: 12 })] : []),
      arrow({ element: arrowRef }),
    ],
  });

  const dismiss = useDismiss(context, {
    enabled: !props.forceFeedbackOpen,
    outsidePressEvent: "mousedown",
  });
  const role = useRole(context, { role: "dialog" });
  const { getFloatingProps } = useInteractions([dismiss, role]);

  const tooltipLabel = props.disabled
    ? `${props.label}不可复制`
    : props.copyStatus === "copied"
      ? `${props.label}已复制`
      : props.copyStatus === "failed"
        ? `${props.label}复制失败`
        : `复制${props.label}`;
  const suppressTooltip = shouldOpenFeedback || props.copyStatus !== "idle";
  const isFailureFeedback = props.copyStatus === "failed";
  const feedbackSubject = props.feedbackSubject || props.label;
  const feedbackTitle = props.copyStatus === "copied" ? "已复制" : "复制失败";
  const feedbackMessage = props.copyStatus === "copied"
    ? (props.successMessage || "已复制")
    : (props.failureMessage || `请手动复制${feedbackSubject}。`);
  const arrowStroke = isFailureFeedback ? "rgba(255,255,255,0.10)" : "rgba(52,211,153,0.22)";
  const arrowFill = isFailureFeedback ? "#0d1728" : "#0b1e1b";
  const arrowWidth = isFailureFeedback ? 16 : 14;
  const arrowHeight = isFailureFeedback ? 8 : 7;
  useEffect(() => {
    if (feedbackTimerRef.current != null) {
      window.clearTimeout(feedbackTimerRef.current);
      feedbackTimerRef.current = null;
    }
    if (!shouldOpenFeedback) {
      setFeedbackOpen(false);
      return;
    }
    setFeedbackOpen(true);
    if (props.autoDismissMs == null || props.forceFeedbackOpen) {
      return;
    }
    feedbackTimerRef.current = window.setTimeout(() => {
      setFeedbackOpen(false);
      feedbackTimerRef.current = null;
    }, props.autoDismissMs);
    return () => {
      if (feedbackTimerRef.current != null) {
        window.clearTimeout(feedbackTimerRef.current);
        feedbackTimerRef.current = null;
      }
    };
  }, [props.autoDismissMs, props.forceFeedbackOpen, shouldOpenFeedback]);

  const button = (
    <Button
      ref={refs.setReference}
      type="button"
      variant="ghost"
      size="icon"
      className={cn(
        props.size === "dense"
          ? "size-5 shrink-0 rounded-md"
          : props.size === "compact"
            ? "size-7 shrink-0 rounded-lg"
            : "size-8 shrink-0 rounded-xl",
        props.copyStatus === "copied"
          ? "text-emerald-200 hover:text-emerald-100"
          : props.copyStatus === "failed"
            ? "text-rose-200 hover:text-rose-100"
            : "text-cyan-200 hover:text-cyan-100",
        props.className,
      )}
      disabled={props.disabled}
      aria-label={tooltipLabel}
      onClick={(event) => {
        event.preventDefault();
        event.stopPropagation();
        if (feedbackEnabled) {
          setFeedbackOpen(true);
        }
        props.onCopy(event.currentTarget);
      }}
    >
      {props.copyStatus === "copied"
        ? <Check className="size-4" aria-hidden="true" />
        : props.idleIcon || <Copy className="size-4" aria-hidden="true" />}
    </Button>
  );

  return (
    <>
      <span className="inline-flex">
        {suppressTooltip ? (
          button
        ) : (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>{button}</TooltipTrigger>
              <TooltipContent>{tooltipLabel}</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
      </span>
      {feedbackEnabled && feedbackOpen ? (
        <FloatingPortal root={props.feedbackPortalContainer ?? null}>
          <div
            ref={refs.setFloating}
            style={floatingStyles}
            className="z-[70] overflow-visible"
            {...getFloatingProps()}
          >
            <div
              className={cn(
                "relative overflow-visible border",
                isFailureFeedback
                  ? "w-[min(calc(100vw-1.5rem),12rem)] rounded-[18px] border-white/10 bg-[linear-gradient(180deg,rgba(12,22,38,0.985),rgba(7,14,27,0.985))] p-2.5 shadow-[0_14px_32px_rgba(2,6,23,0.34)]"
                  : "min-h-[2.75rem] min-w-[5.25rem] rounded-[14px] border-emerald-400/22 bg-[linear-gradient(180deg,rgba(10,33,29,0.985),rgba(8,24,24,0.985))] px-3.5 py-2.5 shadow-[0_8px_18px_rgba(16,185,129,0.10)]",
                props.feedbackContentClassName,
              )}
            >
              <FloatingArrow
                ref={arrowRef}
                context={context}
                width={arrowWidth}
                height={arrowHeight}
                tipRadius={2}
                fill={arrowFill}
                stroke={arrowStroke}
                strokeWidth={1}
                className="drop-shadow-none"
              />
              <div className="space-y-2">
                <div className={cn("min-w-0", isFailureFeedback ? "space-y-1" : "")}> 
                  <div className={cn("font-semibold", isFailureFeedback ? "text-sm text-white" : "text-xs text-emerald-200/90")}>{feedbackTitle}</div>
                  {isFailureFeedback ? (
                    <div className="text-xs leading-5 text-slate-300">{feedbackMessage}</div>
                  ) : null}
                </div>
                {isFailureFeedback && props.feedbackValue != null ? (
                  <div>
                    <div
                      role="textbox"
                      tabIndex={0}
                      aria-label="完整内容（点击全选）"
                      className="rounded-xl border border-white/10 bg-[#0b1423]/90 px-3 py-2 font-mono text-xs text-slate-100 outline-none transition focus-visible:border-cyan-300/50 focus-visible:ring-2 focus-visible:ring-cyan-300/20"
                      onClick={selectCopyContent}
                      onFocus={selectCopyContent}
                    >
                      {props.feedbackValue || "—"}
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        </FloatingPortal>
      ) : null}
    </>
  );
}
