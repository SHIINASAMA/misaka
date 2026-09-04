import { Badge, Card, Group, Table, Text, Title, Anchor, Stack } from "@mantine/core";
import { IconChevronRight, IconNetwork } from "@tabler/icons-react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { getSisters } from "../api";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";

export function SistersPage() {
  const query = useQuery({ queryKey: ["sisters"], queryFn: getSisters, refetchInterval: 5000, refetchIntervalInBackground: false });
  const items = query.data ?? [];
  return <Stack gap="xl"><div><Text className="eyebrow">Network / Sisters</Text><Title order={1} mt={6}>Sisters</Title><Text c="dimmed" mt={6}>The nodes this Sister can see and reach.</Text></div><Card radius="lg" withBorder p={0} style={{ overflow: "hidden" }}>{query.isLoading ? <LoadingState /> : query.isError ? <div style={{ padding: 24 }}><ErrorState error={query.error} onRetry={() => void query.refetch()} /></div> : items.length === 0 ? <EmptyState title="No Sisters yet" message="Start a second node in the same Network to build your first connection." /> : <Table.ScrollContainer minWidth={720}><Table verticalSpacing="md" highlightOnHover><Table.Thead><Table.Tr><Table.Th>Sister</Table.Th><Table.Th>Status</Table.Th><Table.Th>Platform</Table.Th><Table.Th>Resources</Table.Th><Table.Th>Route</Table.Th><Table.Th /></Table.Tr></Table.Thead><Table.Tbody>{items.map((sister) => <Table.Tr key={sister.id}><Table.Td><Group gap="sm"><IconNetwork size={17} color="#67e8f9" /><div><Anchor component={Link} to={`/sisters/${sister.id}`} c="gray.1" fw={600}>{sister.nickname}</Anchor><Text size="xs" c="dimmed" className="mono">#{sister.id} · {sister.hostname}</Text></div></Group></Table.Td><Table.Td><Badge color={sister.status === "online" ? "teal" : "gray"} variant="light">{sister.status}</Badge></Table.Td><Table.Td><Text size="sm">{sister.platform}</Text><Text size="xs" c="dimmed">v{sister.version}</Text></Table.Td><Table.Td><Text size="sm">{sister.cpu_usage.toFixed(1)}% CPU</Text><Text size="xs" c="dimmed">{sister.running_jobs} running</Text></Table.Td><Table.Td><Text size="xs" className="mono" c="dimmed">{sister.stream_endpoints[0] ?? sister.control_endpoint}</Text></Table.Td><Table.Td><IconChevronRight size={16} color="#8490aa" /></Table.Td></Table.Tr>)}</Table.Tbody></Table></Table.ScrollContainer>}</Card></Stack>;
}
