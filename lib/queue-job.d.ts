type Awaitable<T> = () => Promise<T>;
export declare function queueJob<T>(bucket: unknown, awaitable: Awaitable<T>): Promise<T>;
export {};
