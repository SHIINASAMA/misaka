import { Alert, Center, Loader, Stack, Text, Title } from "@mantine/core";
import { IconAlertTriangle, IconInbox } from "@tabler/icons-react";

export function LoadingState({ label = "Reading Sister state" }: { label?: string }) {
  return <Center mih={220}><Stack align="center" gap="sm"><Loader color="cyan" size="sm" /><Text c="dimmed" size="sm">{label}</Text></Stack></Center>;
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry: () => void }) {
  return <Alert icon={<IconAlertTriangle size={18} />} color="yellow" title="API unavailable" withCloseButton={false}>{error.message}. <button className="inline-action" onClick={onRetry}>Try again</button></Alert>;
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return <Center mih={220}><Stack align="center" gap={6}><IconInbox size={30} color="#67e8f9" /><Title order={4}>{title}</Title><Text c="dimmed" size="sm" ta="center" maw={420}>{message}</Text></Stack></Center>;
}
