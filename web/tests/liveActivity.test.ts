import assert from 'node:assert/strict'
import test from 'node:test'
import { activityBuckets } from '../src/liveActivity.ts'

test('groups retained events and finding updates by minute within the visible window', () => {
  const now = 20 * 60_000 + 30_000
  const buckets = activityBuckets([
    { atMs: 18 * 60_000, kind: 'http' },
    { atMs: 20 * 60_000 + 1, kind: 'connection' },
    { atMs: 21 * 60_000, kind: 'http' },
    { atMs: 5 * 60_000, kind: 'http' },
  ], [{ lastMs: 20 * 60_000 + 2 }], now, 3)

  assert.deepEqual(buckets.map(({ http, tcp, findings }) => [http, tcp, findings]), [
    [1, 0, 0], [0, 0, 0], [0, 1, 1],
  ])
})
