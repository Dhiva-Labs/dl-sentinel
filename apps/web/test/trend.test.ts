import { describe, expect, it } from 'vitest';
import {
  pointsToAreaPath,
  pointsToPath,
  seriesMax,
  seriesToPoints,
  severityValues,
} from '../src/trend.js';
import type { TrendPointLike } from '../src/trend.js';

function point(
  finishedAt: string,
  critical: number,
  high: number,
  medium: number,
  low: number,
  info: number,
): TrendPointLike {
  return {
    finishedAt,
    critical,
    high,
    medium,
    low,
    info,
    total: critical + high + medium + low + info,
  };
}

const SAMPLE: TrendPointLike[] = [
  point('2026-02-01T00:00:00.000Z', 0, 1, 1, 0, 0),
  point('2026-02-02T00:00:00.000Z', 1, 2, 0, 0, 0),
  point('2026-02-03T00:00:00.000Z', 2, 0, 0, 1, 3),
];

describe('severityValues', () => {
  it('extracts one series across the points in order', () => {
    expect(severityValues(SAMPLE, 'critical')).toEqual([0, 1, 2]);
    expect(severityValues(SAMPLE, 'total')).toEqual([2, 3, 6]);
  });
});

describe('seriesMax', () => {
  it('returns the largest value across every series', () => {
    expect(
      seriesMax([
        [0, 1, 2],
        [2, 3, 6],
      ]),
    ).toBe(6);
  });

  it('floors at 1 so a flat-zero chart still has a scale', () => {
    expect(seriesMax([[0, 0, 0]])).toBe(1);
    expect(seriesMax([])).toBe(1);
  });
});

describe('seriesToPoints', () => {
  const dims = { width: 100, height: 100, padding: 0 };

  it('spreads x evenly and inverts y against the max', () => {
    expect(seriesToPoints([0, 5, 10], dims, 10)).toEqual([
      { x: 0, y: 100 },
      { x: 50, y: 50 },
      { x: 100, y: 0 },
    ]);
  });

  it('honours padding on both axes', () => {
    expect(seriesToPoints([0, 10], { width: 100, height: 100, padding: 10 }, 10)).toEqual([
      { x: 10, y: 90 },
      { x: 90, y: 10 },
    ]);
  });

  it('centres a single point', () => {
    expect(seriesToPoints([7], dims, 10)).toEqual([{ x: 50, y: 30 }]);
  });

  it('collapses to the baseline when the max is zero', () => {
    expect(seriesToPoints([0, 0], dims, 0)).toEqual([
      { x: 0, y: 100 },
      { x: 100, y: 100 },
    ]);
  });

  it('returns nothing for an empty series', () => {
    expect(seriesToPoints([], dims, 10)).toEqual([]);
  });
});

describe('pointsToPath', () => {
  it('builds a move-then-line SVG path', () => {
    expect(
      pointsToPath([
        { x: 0, y: 100 },
        { x: 50, y: 50 },
        { x: 100, y: 0 },
      ]),
    ).toBe('M 0 100 L 50 50 L 100 0');
  });

  it('is a lone move for a single point', () => {
    expect(pointsToPath([{ x: 50, y: 30 }])).toBe('M 50 30');
  });

  it('is empty for no points', () => {
    expect(pointsToPath([])).toBe('');
  });
});

describe('pointsToAreaPath', () => {
  it('closes the line down to the baseline', () => {
    expect(
      pointsToAreaPath(
        [
          { x: 0, y: 20 },
          { x: 100, y: 60 },
        ],
        100,
      ),
    ).toBe('M 0 20 L 100 60 L 100 100 L 0 100 Z');
  });

  it('is empty for no points', () => {
    expect(pointsToAreaPath([], 100)).toBe('');
  });
});
