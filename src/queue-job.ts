type Awaitable<T> = () => Promise<T>

interface QueuedJob {
	awaitable: Awaitable<unknown>
	resolve: (value: unknown) => void
	reject: (reason?: unknown) => void
}

const _queueAsyncBuckets = new Map<unknown, QueuedJob[]>()
const _gcLimit = 500

async function _asyncQueueExecutor(queue: QueuedJob[], cleanup: () => void): Promise<void> {
	let offt = 0

	while (true) {
		const limit = Math.min(queue.length, _gcLimit)
		for (let i = offt; i < limit; i++) {
			const job = queue[i]!
			try {
				job.resolve(await job.awaitable())
			} catch (e) {
				job.reject(e)
			}
		}

		if (limit < queue.length) {
			queue.splice(0, limit)
			offt = 0
		} else {
			break
		}
	}

	cleanup()
}

export function queueJob<T>(bucket: unknown, awaitable: Awaitable<T>): Promise<T> {
	let inactive = false
	if (!_queueAsyncBuckets.has(bucket)) {
		_queueAsyncBuckets.set(bucket, [])
		inactive = true
	}

	const queue = _queueAsyncBuckets.get(bucket)!
	const job = new Promise<T>((resolve, reject) =>
		queue.push({
			awaitable: awaitable as Awaitable<unknown>,
			resolve: resolve as (value: unknown) => void,
			reject
		})
	)

	if (inactive) {
		_asyncQueueExecutor(queue, () => _queueAsyncBuckets.delete(bucket))
	}

	return job
}
