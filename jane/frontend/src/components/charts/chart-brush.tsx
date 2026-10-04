"use client";

import * as React from "react";
import { createPortal } from "react-dom";
import { Brush } from "@visx/brush";
import { cn } from "@/lib/utils";
import { useChartStable, chartCssVars } from "./chart-context";
import { resolveBrushTrackXExtent } from "./filter-data-by-x-domain";
import { renderPatternPreset, type PatternPresetId, type PatternPresetOptions } from "./pattern-preset";

function parseDate(e: unknown): Date {
  return e instanceof Date ? e : new Date(typeof e === "number" ? e : Number(e));
}

function getOuterEdgeStyle(
  direction: "left" | "right",
  options: { blurPx: number; fadeOuterEdges: boolean }
): React.CSSProperties {
  let maskImage: string | undefined;
  const fade = "15%";
  if (options.fadeOuterEdges) {
    maskImage =
      direction === "left"
        ? `linear-gradient(to right, transparent 0%, black ${fade}, black 100%)`
        : `linear-gradient(to left, transparent 0%, black ${fade}, black 100%)`;
  }
  return {
    pointerEvents: "none",
    backdropFilter: options.blurPx > 0 ? `blur(${options.blurPx}px)` : undefined,
    WebkitBackdropFilter: options.blurPx > 0 ? `blur(${options.blurPx}px)` : undefined,
    maskImage,
    WebkitMaskImage: maskImage,
  };
}

function OuterEdgesOverlay({
  containerRef,
  margin,
  innerWidth,
  innerHeight,
  selectionX0,
  selectionX1,
  blurPx = 1.5,
  fadeOuterEdges = true,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>;
  margin: { top: number; left: number; right: number; bottom: number };
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
  blurPx?: number;
  fadeOuterEdges?: boolean;
}) {
  const [mounted, setMounted] = React.useState(false);
  const options = React.useMemo(
    () => ({
      blurPx: Math.min(5, Math.max(0, blurPx)),
      fadeOuterEdges,
    }),
    [blurPx, fadeOuterEdges]
  );

  React.useEffect(() => {
    setMounted(true);
  }, []);

  const container = containerRef.current;
  if (!(mounted && container)) return null;

  const minX = Math.max(0, Math.min(selectionX0, selectionX1, innerWidth));
  const maxX = Math.max(minX, Math.min(Math.max(selectionX0, selectionX1), innerWidth));
  const leftWidth = Math.max(0, minX);
  const rightWidth = Math.max(0, innerWidth - maxX);

  if (leftWidth <= 0 && rightWidth <= 0) return null;

  const left = margin.left;
  const top = margin.top;

  return createPortal(
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 z-[1]">
      {leftWidth > 0 && (
        <div
          className="absolute"
          style={{
            ...getOuterEdgeStyle("left", options),
            top,
            left,
            width: leftWidth,
            height: innerHeight,
          }}
        />
      )}
      {rightWidth > 0 && (
        <div
          className="absolute"
          style={{
            ...getOuterEdgeStyle("right", options),
            top,
            left: left + maxX,
            width: rightWidth,
            height: innerHeight,
          }}
        />
      )}
    </div>,
    container
  );
}

function OuterEdgesPortal(props: {
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
  blurPx?: number;
  fadeOuterEdges?: boolean;
}) {
  const { containerRef, margin } = useChartStable();
  return <OuterEdgesOverlay {...props} containerRef={containerRef} margin={margin} />;
}

function BrushHandlesPortal({
  containerRef,
  margin,
  innerWidth,
  innerHeight,
  selectionX0,
  selectionX1,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>;
  margin: { top: number; left: number };
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
}) {
  const [mounted, setMounted] = React.useState(false);
  React.useEffect(() => {
    setMounted(true);
  }, []);

  const container = containerRef.current;
  if (!(mounted && container)) return null;

  const minX = Math.max(0, Math.min(selectionX0, selectionX1, innerWidth));
  const maxX = Math.max(minX, Math.min(Math.max(selectionX0, selectionX1), innerWidth));
  const left = margin.left;
  const top = margin.top + (innerHeight - 24) / 2;
  const positions = minX === maxX ? [minX] : [minX, maxX];

  return createPortal(
    <div aria-hidden="true" className="pointer-events-none absolute inset-0 z-[2]">
      {positions.map((pos, idx) => (
        <div
          key={idx}
          className="absolute shrink-0 rounded-lg"
          style={{
            top,
            left: left + pos - 2,
            width: 4,
            height: 24,
            backgroundColor: "var(--chart-brush-border, #a1a1aa)",
          }}
        />
      ))}
    </div>,
    container
  );
}

function HandlesOverlay(props: {
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
}) {
  const { containerRef, margin } = useChartStable();
  return <BrushHandlesPortal {...props} containerRef={containerRef} margin={margin} />;
}

function BrushPatternOverlay({
  containerRef,
  margin,
  innerWidth,
  innerHeight,
  selectionX0,
  selectionX1,
  pattern,
}: {
  containerRef: React.RefObject<HTMLDivElement | null>;
  margin: { top: number; left: number };
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
  pattern?: { preset: PatternPresetId; opacity?: number } & PatternPresetOptions;
}) {
  const [mounted, setMounted] = React.useState(false);
  const patternId = React.useId().replace(/:/g, "");
  React.useEffect(() => {
    setMounted(true);
  }, []);

  const container = containerRef.current;
  if (!(mounted && container && pattern && pattern.preset !== "none")) return null;

  const minX = Math.max(0, Math.min(selectionX0, selectionX1, innerWidth));
  const width = Math.max(minX, Math.min(Math.max(selectionX0, selectionX1), innerWidth)) - minX;
  if (width <= 0) return null;

  const left = margin.left;
  const top = margin.top;
  const patternEl = renderPatternPreset(pattern.preset, patternId, pattern);

  if (!patternEl) return null;

  return createPortal(
    <svg aria-hidden="true" className="pointer-events-none absolute inset-0 z-[1]" height="100%" width="100%">
      <defs>{patternEl}</defs>
      <rect
        fill={`url(#${patternId})`}
        fillOpacity={pattern.opacity ?? 1}
        height={innerHeight}
        width={width}
        x={left + minX}
        y={top}
      />
    </svg>,
    container
  );
}

function PatternOverlay(props: {
  innerWidth: number;
  innerHeight: number;
  selectionX0: number;
  selectionX1: number;
  pattern?: { preset: PatternPresetId; opacity?: number } & PatternPresetOptions;
}) {
  const { containerRef, margin } = useChartStable();
  return <BrushPatternOverlay {...props} containerRef={containerRef} margin={margin} />;
}

function renderBrushHandle({ x, y, width, height, className }: any) {
  return (
    <rect
      className={className}
      fill="transparent"
      height={height}
      width={width}
      x={x}
      y={y}
      style={{
        cursor: className?.includes("left") || className?.includes("right") ? "ew-resize" : "ns-resize",
      }}
    />
  );
}

interface BrushInternalProps {
  brushDirection?: "horizontal" | "vertical" | "both";
  selectedBoxStyle?: React.SVGProps<SVGRectElement>;
  initialSelection?: { start: Date; end: Date };
  useWindowMoveEvents?: boolean;
  xScale: any;
  yScale: any;
  innerWidth: number;
  innerHeight: number;
  margin: { top: number; left: number; right: number; bottom: number };
  onBrushPreview?: (extent: any) => void;
  onBrushCommit?: (extent: any) => void;
  blurPx?: number;
  fadeOuterEdges?: boolean;
  selectionPattern?: { preset: PatternPresetId; opacity?: number } & PatternPresetOptions;
}

const BrushInternal = React.memo(function BrushInternal({
  brushDirection = "horizontal",
  selectedBoxStyle,
  initialSelection,
  useWindowMoveEvents = true,
  xScale,
  yScale,
  innerWidth,
  innerHeight,
  margin,
  onBrushPreview,
  onBrushCommit,
  blurPx,
  fadeOuterEdges,
  selectionPattern,
}: BrushInternalProps) {
  const initialBrushPosition = React.useMemo(() => {
    if (!initialSelection || innerWidth <= 0 || innerHeight <= 0 || !xScale) return undefined;
    const x0 = Math.max(0, xScale(initialSelection.start) ?? 0);
    const x1 = Math.min(innerWidth, xScale(initialSelection.end) ?? innerWidth);
    if (x1 <= x0) return undefined;
    return {
      start: { x: x0, y: 0 },
      end: { x: x1, y: innerHeight },
    };
  }, [initialSelection, xScale, innerWidth, innerHeight]);

  const [coords, setCoords] = React.useState(() => ({
    x0: initialBrushPosition?.start.x ?? 0,
    x1: initialBrushPosition?.end.x ?? innerWidth,
  }));

  React.useEffect(() => {
    setCoords({
      x0: initialBrushPosition?.start.x ?? 0,
      x1: initialBrushPosition?.end.x ?? innerWidth,
    });
  }, [initialBrushPosition, innerWidth]);

  const syncCoords = React.useCallback(
    (extent: any) => {
      if (!extent || extent.x0 === undefined || extent.x1 === undefined || !xScale) return null;
      const d0 = parseDate(extent.x0);
      const d1 = parseDate(extent.x1);
      const start = Math.max(0, xScale(d0 < d1 ? d0 : d1) ?? 0);
      const end = Math.min(innerWidth, xScale(d1 > d0 ? d1 : d0) ?? innerWidth);
      if (end <= start) return null;
      const next = { x0: start, x1: end };
      setCoords(next);
      return next;
    },
    [innerWidth, xScale]
  );

  const handleChange = React.useCallback(
    (extent: any) => {
      syncCoords(extent);
      onBrushPreview?.(extent);
    },
    [onBrushPreview, syncCoords]
  );

  const handleBrushEnd = React.useCallback(
    (extent: any) => {
      syncCoords(extent);
      onBrushCommit?.(extent);
    },
    [onBrushCommit, syncCoords]
  );

  const defaultBoxStyle = React.useMemo(
    () => ({
      fill: "transparent",
      fillOpacity: 0,
      stroke: chartCssVars.brushBorder,
      strokeWidth: 1,
    }),
    []
  );

  return (
    <g className="chart-brush">
      <OuterEdgesPortal
        blurPx={blurPx}
        fadeOuterEdges={fadeOuterEdges}
        innerHeight={innerHeight}
        innerWidth={innerWidth}
        selectionX0={coords.x0}
        selectionX1={coords.x1}
      />
      <PatternOverlay
        innerHeight={innerHeight}
        innerWidth={innerWidth}
        pattern={selectionPattern}
        selectionX0={coords.x0}
        selectionX1={coords.x1}
      />
      <HandlesOverlay
        innerHeight={innerHeight}
        innerWidth={innerWidth}
        selectionX0={coords.x0}
        selectionX1={coords.x1}
      />
      <Brush
        brushDirection={brushDirection}
        handleSize={8}
        height={innerHeight}
        initialBrushPosition={initialBrushPosition}
        margin={useWindowMoveEvents ? margin : { top: 0, left: 0, right: 0, bottom: 0 }}
        onBrushEnd={handleBrushEnd}
        onChange={handleChange}
        renderBrushHandle={renderBrushHandle}
        selectedBoxStyle={selectedBoxStyle ?? defaultBoxStyle}
        useWindowMoveEvents={useWindowMoveEvents}
        width={innerWidth}
        xScale={xScale}
        yScale={yScale}
        key={`brush-${innerWidth}-${innerHeight}`}
      />
    </g>
  );
});

export interface ChartBrushProps {
  onSelectionChange?: (selection: { start: Date; end: Date } | null) => void;
  brushDirection?: "horizontal" | "vertical" | "both";
  selectedBoxStyle?: React.SVGProps<SVGRectElement>;
  initialSelection?: { start: Date; end: Date };
  selection?: { start: Date; end: Date };
  useWindowMoveEvents?: boolean;
  blurPx?: number;
  fadeOuterEdges?: boolean;
  selectionPattern?: { preset: PatternPresetId; opacity?: number } & PatternPresetOptions;
}

export function ChartBrush({
  onSelectionChange,
  brushDirection = "horizontal",
  selectedBoxStyle,
  initialSelection,
  useWindowMoveEvents = true,
  blurPx,
  fadeOuterEdges,
  selectionPattern,
}: ChartBrushProps) {
  const { xScale, yScale, innerWidth, innerHeight, margin, isLoaded } = useChartStable();

  const convertExtent = React.useCallback((extent: any): { start: Date; end: Date } | null => {
    if (!extent || extent.x0 === undefined || extent.x1 === undefined) return null;
    const t0 = parseDate(extent.x0);
    const t1 = parseDate(extent.x1);
    if (t0.getTime() === t1.getTime()) return null;
    return {
      start: t0 < t1 ? t0 : t1,
      end: t1 > t0 ? t1 : t0,
    };
  }, []);

  const notifyChange = React.useCallback(
    (extent: any) => {
      if (onSelectionChange) {
        onSelectionChange(convertExtent(extent));
      }
    },
    [convertExtent, onSelectionChange]
  );

  if (!isLoaded || innerWidth <= 0 || innerHeight <= 0) {
    return null;
  }

  return (
    <BrushInternal
      blurPx={blurPx}
      brushDirection={brushDirection}
      fadeOuterEdges={fadeOuterEdges}
      initialSelection={initialSelection}
      innerHeight={innerHeight}
      innerWidth={innerWidth}
      margin={margin}
      onBrushCommit={notifyChange}
      onBrushPreview={notifyChange}
      selectedBoxStyle={selectedBoxStyle}
      selectionPattern={selectionPattern}
      useWindowMoveEvents={useWindowMoveEvents}
      xScale={xScale}
      yScale={yScale}
    />
  );
}

ChartBrush.displayName = "ChartBrush";

export interface ChartBrushLayoutContext {
  xDomain?: [Date, Date];
  xDomainSlotCount?: number;
  brushSelection: { start: Date; end: Date } | null;
  onBrushSelectionChange: (selection: { start: Date; end: Date } | null) => void;
}

export interface ChartBrushLayoutProps<T = any> {
  data: T[];
  xDataKey?: string;
  xExtentMax?: Date;
  enabled?: boolean;
  height?: number;
  fitMainContent?: boolean;
  className?: string;
  children: (layout: ChartBrushLayoutContext) => React.ReactNode;
  brushStrip?: (layout: ChartBrushLayoutContext) => React.ReactNode;
}

export const ChartBrushLayout = React.memo(function ChartBrushLayout<T extends Record<string, any>>({
  data,
  xDataKey = "date",
  xExtentMax,
  enabled,
  height,
  fitMainContent = false,
  className,
  children,
  brushStrip,
}: ChartBrushLayoutProps<T>) {
  const getX = React.useMemo(
    () => (d: T) => {
      const val = d[xDataKey];
      return val instanceof Date ? val : new Date(val);
    },
    [xDataKey]
  );

  const extent = React.useMemo(
    () =>
      resolveBrushTrackXExtent(
        data as unknown as Record<string, unknown>[],
        getX as (d: Record<string, unknown>) => Date,
        xExtentMax
      ),
    [data, getX, xExtentMax]
  );

  const [brushSelection, setBrushSelection] = React.useState<{ start: Date; end: Date } | null>(null);

  React.useEffect(() => {
    if (extent) {
      setBrushSelection({ start: extent[0], end: extent[1] });
    } else {
      setBrushSelection(null);
    }
  }, [extent]);

  const onBrushSelectionChange = React.useCallback(
    (selection: { start: Date; end: Date } | null) => {
      if (!selection) {
        if (extent) {
          setBrushSelection({ start: extent[0], end: extent[1] });
        }
        return;
      }
      setBrushSelection(selection);
    },
    [extent]
  );

  const layoutContext = React.useMemo<ChartBrushLayoutContext>(
    () => ({
      xDomain: enabled && brushSelection ? [brushSelection.start, brushSelection.end] : undefined,
      xDomainSlotCount: enabled ? data.length : undefined,
      brushSelection,
      onBrushSelectionChange,
    }),
    [brushSelection, data.length, enabled, onBrushSelectionChange]
  );

  return (
    <div className={cn("flex size-full min-h-0 min-w-0 flex-col", fitMainContent ? "justify-start gap-1" : "gap-3", className)}>
      <div className={cn("min-h-0 min-w-0", fitMainContent ? "shrink-0" : "flex-1")}>
        {children(layoutContext)}
      </div>
      {enabled && brushStrip && (
        <div className="min-h-0 shrink-0" style={{ height }}>
          {brushStrip(layoutContext)}
        </div>
      )}
    </div>
  );
});
