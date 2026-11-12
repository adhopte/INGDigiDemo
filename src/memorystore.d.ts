declare module 'memorystore' {
  import type session from 'express-session';
  export default function memorystore(s: typeof session): new (opts?: { checkPeriod?: number; ttl?: number; max?: number }) => session.Store;
}
