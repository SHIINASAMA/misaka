import type { NetworkStream, Overview, Sister } from "./types";

const apiOrigin = import.meta.env.VITE_MISAKA_API_URL ?? "";

export async function requestJson<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiOrigin}${path}`, {
    ...init,
    headers: { Accept: "application/json", ...init?.headers },
  });

  if (!response.ok) {
    let message = `API request failed (${response.status})`;
    try {
      const body = (await response.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      // Keep the status-based message when the server did not return JSON.
    }
    throw new Error(message);
  }

  return (await response.json()) as T;
}

export const getOverview = () => requestJson<Overview>("/api/v1/overview");
export const getSisters = () => requestJson<Sister[]>("/api/v1/sisters");
export const getSister = (id: string) => requestJson<Sister>(`/api/v1/sisters/${id}`);
export const getStreams = () => requestJson<NetworkStream[]>("/api/v1/streams");

export const pingSister = (id: string) =>
  requestJson<{ sister_id: string; status: string }>(`/api/v1/sisters/${id}/ping`, {
    method: "POST",
  });

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

export function formatDuration(milliseconds: number): string {
  const seconds = Math.floor(milliseconds / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

export function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
}
