// Minimal ambient declarations for the Vite dev-server config, which runs in
// Node but has no @types/node dev-dependency in this repository.
declare module "node:fs" {
  export function readFileSync(path: string, encoding: string): string;
}
declare module "node:os" {
  export function homedir(): string;
}
declare module "node:path" {
  export function join(...parts: string[]): string;
}
declare const process: { env: Record<string, string | undefined> };
declare const console: { warn(...args: unknown[]): void };
