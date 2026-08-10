/**
 * Pure geometry for the dashboard's dependency-free trend chart, mirrored in
 * public/app.js (which builds the actual SVG DOM nodes from these numbers).
 * Kept here as the typechecked, unit-tested source of truth so the coordinate
 * math is verified independently of the DOM.
 */

import type { Severity } from './types.js';

/** One completed scan reduced to plottable severity counts (mirrors the API's TrendPoint). */
export interface TrendPointLike {
  finishedAt: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

/** A key selecting one plottable series from a trend point. */
export type TrendKey = Severity | 'total';

export interface XYPoint {
  x: number;
  y: number;
}

export interface ChartDims {
  width: number;
  height: number;
  /** Uniform inner margin so points and axes are not flush against the edges. */
  padding: number;
}

/** Round to 2 decimals so generated path strings are stable and compact. */
function round2(value: number): number {
  return Math.round(value * 100) / 100;
}

/** Pull one numeric series (a severity, or the total) across the points, in order. */
export function severityValues(points: readonly TrendPointLike[], key: TrendKey): number[] {
  return points.map((point) => point[key]);
}

/** The largest value across the given series, floored at 1 so a flat-zero chart still has a scale. */
export function seriesMax(seriesList: ReadonlyArray<readonly number[]>): number {
  let max = 0;
  for (const series of seriesList) {
    for (const value of series) {
      if (value > max) max = value;
    }
  }
  return max <= 0 ? 1 : max;
}

/**
 * Map a numeric series to (x, y) points inside a padded chart box. x is spread
 * evenly across the inner width (a single point is centred); y is inverted so
 * larger values sit higher, scaled against `maxValue`. A non-positive
 * `maxValue` collapses every point to the baseline.
 */
export function seriesToPoints(
  values: readonly number[],
  dims: ChartDims,
  maxValue: number,
): XYPoint[] {
  const { width, height, padding } = dims;
  const innerWidth = width - padding * 2;
  const innerHeight = height - padding * 2;
  const baseline = height - padding;
  const n = values.length;
  return values.map((value, i) => {
    let x: number;
    if (n <= 1) x = padding + innerWidth / 2;
    else x = padding + (i / (n - 1)) * innerWidth;
    const y = maxValue > 0 ? baseline - (value / maxValue) * innerHeight : baseline;
    return { x: round2(x), y: round2(y) };
  });
}

/** Build an SVG path `d` string ("M x y L x y …") from points; "" for none. */
export function pointsToPath(points: readonly XYPoint[]): string {
  if (points.length === 0) return '';
  return points.map((point, i) => `${i === 0 ? 'M' : 'L'} ${point.x} ${point.y}`).join(' ');
}

/**
 * Close a line path into a filled area by dropping to the baseline under the
 * last and first points. Returns "" when there are no points.
 */
export function pointsToAreaPath(points: readonly XYPoint[], baselineY: number): string {
  if (points.length === 0) return '';
  const line = pointsToPath(points);
  const last = points[points.length - 1];
  const first = points[0];
  if (last === undefined || first === undefined) return '';
  return `${line} L ${round2(last.x)} ${round2(baselineY)} L ${round2(first.x)} ${round2(baselineY)} Z`;
}
