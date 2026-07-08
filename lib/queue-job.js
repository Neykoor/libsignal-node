const _queueAsyncBuckets = new Map();
const _gcLimit = 500;
async function _asyncQueueExecutor(queue, cleanup) {
    let offt = 0;
    while (true) {
        const limit = Math.min(queue.length, _gcLimit);
        for (let i = offt; i < limit; i++) {
            const job = queue[i];
            try {
                job.resolve(await job.awaitable());
            }
            catch (e) {
                job.reject(e);
            }
        }
        if (limit < queue.length) {
            queue.splice(0, limit);
            offt = 0;
        }
        else {
            break;
        }
    }
    cleanup();
}
export function queueJob(bucket, awaitable) {
    const namedAwaitable = awaitable;
    if (!namedAwaitable.name) {
        Object.defineProperty(namedAwaitable, 'name', { writable: true });
        if (typeof bucket === 'string') {
            namedAwaitable.name = bucket;
        }
    }
    let inactive = false;
    if (!_queueAsyncBuckets.has(bucket)) {
        _queueAsyncBuckets.set(bucket, []);
        inactive = true;
    }
    const queue = _queueAsyncBuckets.get(bucket);
    const job = new Promise((resolve, reject) => queue.push({
        awaitable: awaitable,
        resolve: resolve,
        reject
    }));
    if (inactive) {
        _asyncQueueExecutor(queue, () => _queueAsyncBuckets.delete(bucket));
    }
    return job;
}
