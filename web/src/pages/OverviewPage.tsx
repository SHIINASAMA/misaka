import { Badge, Card, Group, Progress, SimpleGrid, Skeleton, Stack, Text, Title } from "@mantine/core";
import { IconActivity, IconCpu, IconDatabase, IconNetwork, IconRoute } from "@tabler/icons-react";
import { useQuery } from "@tanstack/react-query";
import { getOverview, getSisters, formatBytes } from "../api";
import { ConnectionRail } from "../components/ConnectionRail";
import { EmptyState, ErrorState } from "../components/StateViews";

export function OverviewPage() {
  const overview = useQuery({ queryKey: ["overview"], queryFn: getOverview, refetchInterval: 5000, refetchIntervalInBackground: false });
  const sisters = useQuery({ queryKey: ["sisters"], queryFn: getSisters, refetchInterval: 5000, refetchIntervalInBackground: false });
  if (overview.isLoading || sisters.isLoading) return <><PageHeading eyebrow="Network / Overview" title="Your network, at a glance" /><Skeleton height={180} radius="lg" /><Skeleton height={180} mt="lg" radius="lg" /></>;
  if (overview.isError) return <><PageHeading eyebrow="Network / Overview" title="Your network, at a glance" /><ErrorState error={overview.error} onRetry={() => void overview.refetch()} /></>;
  if (sisters.isError) return <><PageHeading eyebrow="Network / Overview" title="Your network, at a glance" /><ErrorState error={sisters.error} onRetry={() => void sisters.refetch()} /></>;
  if (!overview.data || !sisters.data) return <><PageHeading eyebrow="Network / Overview" title="Your network, at a glance" /><Skeleton height={180} radius="lg" /></>;
  const data = overview.data;
  const nodes = sisters.data;
  return <Stack gap="xl">
    <PageHeading eyebrow="Network / Overview" title="Your network, at a glance" description={`Namespace ${data.network_id}`} action={<Badge color="teal" variant="light" leftSection={<IconActivity size={12} />}>Runtime online</Badge>} />
    <Card className="hero-card" radius="lg" p={{ base: "lg", sm: "xl" }} withBorder>
      <Group justify="space-between" align="flex-start" mb="xl"><div><Text className="eyebrow">Connection pulse</Text><Title order={2} mt={5}>A living network</Title><Text c="dimmed" mt={6}>Every node here is a Sister. The rail reflects what this runtime knows now.</Text></div><IconRoute size={30} color="#67e8f9" stroke={1.3} /></Group>
      {nodes.length ? <ConnectionRail sisters={nodes} localId={data.this_sister} /> : <EmptyState title="No Sisters discovered yet" message="Start another Sister with the same NetworkId or add a peer to see it here." />}
    </Card>
    <SimpleGrid cols={{ base: 1, xs: 2, md: 4 }}>
      <Metric icon={<IconNetwork size={18} />} label="Online Sisters" value={`${data.online_sisters}`} detail={`${data.known_sisters} known`} />
      <Metric icon={<IconActivity size={18} />} label="Active streams" value={`${data.active_streams}`} detail="live transport paths" />
      <Metric icon={<IconCpu size={18} />} label="This Sister" value={`#${data.this_sister}`} detail={data.this_nickname} />
      <Metric icon={<IconDatabase size={18} />} label="Version" value={data.version} detail="runtime" />
    </SimpleGrid>
    <Card radius="lg" p="lg" withBorder><Group justify="space-between" mb="lg"><div><Text className="eyebrow">Local resources</Text><Title order={4} mt={4}>Capacity snapshot</Title></div><Text size="sm" c="dimmed">Live from Sister runtime</Text></Group><ResourceSummary sisters={nodes} /></Card>
  </Stack>;
}

function PageHeading({ eyebrow, title, description, action }: { eyebrow: string; title: string; description?: string; action?: React.ReactNode }) { return <Group justify="space-between" align="flex-end"><div><Text className="eyebrow">{eyebrow}</Text><Title order={1} mt={6}>{title}</Title>{description && <Text c="dimmed" mt={6}>{description}</Text>}</div>{action}</Group>; }
function Metric({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: string; detail: string }) { return <Card radius="lg" p="lg" withBorder><Group gap="sm" mb="md"><span style={{ color: "#67e8f9" }}>{icon}</span><Text size="sm" c="dimmed">{label}</Text></Group><Title order={2}>{value}</Title><Text size="xs" c="dimmed" mt={5}>{detail}</Text></Card>; }
function ResourceSummary({ sisters }: { sisters: import("../types").Sister[] }) { const local = sisters[0]; if (!local) return <Text c="dimmed" size="sm">Resource data will appear when the local Sister is available.</Text>; const memory = local.memory_total ? Math.round((local.memory_used / local.memory_total) * 100) : 0; return <SimpleGrid cols={{ base: 1, sm: 3 }}><Resource icon={<IconCpu size={16} />} label="CPU" value={`${local.cpu_usage.toFixed(1)}%`} progress={Math.min(local.cpu_usage, 100)} /><Resource icon={<IconDatabase size={16} />} label="Memory" value={`${formatBytes(local.memory_used)} / ${formatBytes(local.memory_total)}`} progress={memory} /><Resource icon={<IconActivity size={16} />} label="Jobs" value={`${local.running_jobs} running · ${local.queued_jobs} queued`} progress={0} /></SimpleGrid>; }
function Resource({ icon, label, value, progress }: { icon: React.ReactNode; label: string; value: string; progress: number }) { return <div><Group justify="space-between" mb={7}><Group gap={6}><span style={{ color: "#8490aa" }}>{icon}</span><Text size="sm">{label}</Text></Group><Text size="xs" c="dimmed" className="mono">{value}</Text></Group><Progress value={progress} color={progress > 80 ? "yellow" : "cyan"} size="sm" radius="xl" /></div>; }
