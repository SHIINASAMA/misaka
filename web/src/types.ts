export interface Overview {
  network_id: string;
  this_sister: number;
  this_nickname: string;
  online_sisters: number;
  known_sisters: number;
  active_streams: number;
  version: string;
}

export interface Sister {
  id: number;
  nickname: string;
  hostname: string;
  platform: string;
  version: string;
  status: "online" | "offline" | string;
  control_endpoint: string;
  stream_endpoints: string[];
  cpu_usage: number;
  memory_total: number;
  memory_used: number;
  running_jobs: number;
  queued_jobs: number;
  uptime_secs: number;
  capabilities: string[];
}

export interface NetworkStream {
  stream_id: number;
  backend: string;
  route: string;
  rtt_ms: number | null;
  path_switches: number;
  local_endpoint: string | null;
  remote_endpoint: string | null;
  connected_for_ms: number;
  tx_bytes: number;
  rx_bytes: number;
}

export interface ApiErrorResponse {
  error: string;
}
