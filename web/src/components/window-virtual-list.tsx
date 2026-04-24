import { useLayoutEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useWindowVirtualizer } from "@tanstack/react-virtual";
import { useMediaQuery } from "@/hooks/use-media-query";

type WindowVirtualListProps<T> = {
  items: T[];
  getKey: (item: T, index: number) => string | number;
  estimateSize: (isCompactLayout: boolean, index: number) => number;
  renderItem: (item: T, index: number, isCompactLayout: boolean) => ReactNode;
  compactQuery?: string;
  overscan?: number;
  className?: string;
  measureItems?: boolean;
};

export function WindowVirtualList<T>({
  items,
  getKey,
  estimateSize,
  renderItem,
  compactQuery = "(max-width: 767px)",
  overscan = 6,
  className,
  measureItems = false,
}: WindowVirtualListProps<T>) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const isCompactLayout = useMediaQuery(compactQuery, false);
  const [scrollMargin, setScrollMargin] = useState(0);

  useLayoutEffect(() => {
    if (typeof window === "undefined") return;
    let frameId = 0;
    const updateOffset = () => {
      frameId = 0;
      const container = containerRef.current;
      const nextOffset = container ? container.getBoundingClientRect().top + window.scrollY : 0;
      setScrollMargin((current) => (current === nextOffset ? current : nextOffset));
    };

    const scheduleOffsetUpdate = () => {
      if (frameId !== 0) return;
      frameId = window.requestAnimationFrame(updateOffset);
    };

    scheduleOffsetUpdate();
    window.addEventListener("resize", scheduleOffsetUpdate);

    const resizeObserver =
      typeof ResizeObserver === "undefined" ? null : new ResizeObserver(() => scheduleOffsetUpdate());
    if (resizeObserver) {
      let current: Element | null = containerRef.current;
      while (current) {
        resizeObserver.observe(current);
        current = current.parentElement;
      }
    }

    return () => {
      if (frameId !== 0) {
        window.cancelAnimationFrame(frameId);
      }
      window.removeEventListener("resize", scheduleOffsetUpdate);
      resizeObserver?.disconnect();
    };
  }, [isCompactLayout, items.length]);

  const itemKeys = useMemo(() => items.map((item, index) => getKey(item, index)), [getKey, items]);
  const virtualizer = useWindowVirtualizer({
    count: items.length,
    estimateSize: (index) => estimateSize(isCompactLayout, index),
    overscan,
    scrollMargin,
    getItemKey: (index) => itemKeys[index] ?? index,
  });

  return (
    <div ref={containerRef} className={className}>
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((virtualItem) => {
          const item = items[virtualItem.index];
          if (!item) return null;
          return (
            <div
              key={virtualItem.key}
              data-index={virtualItem.index}
              ref={measureItems ? virtualizer.measureElement : undefined}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${virtualItem.start - scrollMargin}px)`,
              }}
            >
              {renderItem(item, virtualItem.index, isCompactLayout)}
            </div>
          );
        })}
      </div>
    </div>
  );
}
