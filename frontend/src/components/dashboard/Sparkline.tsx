interface SparklineProps {
  values: number[];
  max?: number;
  className?: string;
}

/** A tiny line of the last samples; drawn with plain SVG. */
export function Sparkline({ values, max = 100, className = "" }: SparklineProps) {
  if (values.length < 2) {
    return <div className={`h-8 ${className}`} />;
  }
  const w = 100;
  const h = 30;
  const step = w / (values.length - 1);
  const points = values
    .map((v, i) => {
      const y = h - (Math.min(Math.max(v, 0), max) / max) * h;
      return `${(i * step).toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return (
    <svg
      viewBox={`0 0 ${w} ${h}`}
      preserveAspectRatio="none"
      className={`h-8 w-full ${className}`}
      aria-hidden="true"
    >
      <polyline
        points={points}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
