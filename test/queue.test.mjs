import { describe, it } from "node:test"
import assert from "node:assert/strict"
import { queueJob } from "../lib/queue-job.js"

describe("queueJob", () => {
  it("serializes jobs that share a bucket", async () => {
    let active = 0
    let maxActive = 0
    const order = []

    const jobs = Array.from({ length: 20 }, (_, index) =>
      queueJob("bucket", async () => {
        active++
        maxActive = Math.max(maxActive, active)
        await new Promise((resolve) => setTimeout(resolve, 1))
        order.push(index)
        active--
        return index
      })
    )

    const results = await Promise.all(jobs)
    assert.deepEqual(results, Array.from({ length: 20 }, (_, index) => index))
    assert.deepEqual(order, Array.from({ length: 20 }, (_, index) => index))
    assert.equal(maxActive, 1)
  })

  it("allows independent buckets to run concurrently", async () => {
    let active = 0
    let maxActive = 0

    const job = (bucket) =>
      queueJob(bucket, async () => {
        active++
        maxActive = Math.max(maxActive, active)
        await new Promise((resolve) => setTimeout(resolve, 10))
        active--
      })

    await Promise.all([job("a"), job("b"), job("c")])
    assert.ok(maxActive > 1)
  })

  it("keeps processing after a job rejects", async () => {
    const failed = queueJob("errors", async () => {
      throw new Error("boom")
    })
    const after = queueJob("errors", async () => "ok")

    await assert.rejects(() => failed, /boom/)
    assert.equal(await after, "ok")
  })

  it("handles batches larger than the internal GC limit in order", async () => {
    const order = []
    const jobs = Array.from({ length: 600 }, (_, index) =>
      queueJob("large", async () => {
        order.push(index)
        return index
      })
    )
    const results = await Promise.all(jobs)
    assert.equal(results.length, 600)
    assert.deepEqual(order, Array.from({ length: 600 }, (_, index) => index))
  })
})
