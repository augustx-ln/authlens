const MINUTE = 60_000

export type ActivityBucket = {
  atMs: number
  http: number
  tcp: number
  findings: number
}

export function activityBuckets(
  events: { atMs: number; kind: 'http' | 'connection' }[],
  findings: { lastMs: number }[],
  now: number,
  minutes = 15,
): ActivityBucket[] {
  const start = Math.floor(now / MINUTE) * MINUTE - (minutes - 1) * MINUTE
  const buckets = Array.from({ length: minutes }, (_, index) => ({
    atMs: start + index * MINUTE,
    http: 0,
    tcp: 0,
    findings: 0,
  }))

  for (const event of events) {
    const index = Math.floor((event.atMs - start) / MINUTE)
    if (index >= 0 && index < minutes) buckets[index][event.kind === 'http' ? 'http' : 'tcp']++
  }
  for (const finding of findings) {
    const index = Math.floor((finding.lastMs - start) / MINUTE)
    if (index >= 0 && index < minutes) buckets[index].findings++
  }
  return buckets
}
