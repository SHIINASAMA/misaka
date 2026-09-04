import { Badge, Paper, Stack, Text } from "@mantine/core";
import { IconAntennaBars5 } from "@tabler/icons-react";
import type { Sister } from "../types";

export function ConnectionRail({ sisters, localId }: { sisters: Sister[]; localId?: string }) {
  if (sisters.length === 0) return null;
  return <div className="pulse-rail">
    {sisters.map((sister) => <Paper className="pulse-node" key={sister.id} p="sm" radius="lg" withBorder>
      <Text size="xs" fw={700} truncate>{sister.id === localId ? "This Sister" : sister.nickname}</Text>
      <div className={`pulse-dot ${sister.status === "offline" ? "offline" : ""}`} />
      <Stack gap={2} align="center">
        <Badge variant="light" color={sister.status === "online" ? "teal" : "gray"} size="xs" leftSection={<IconAntennaBars5 size={11} />}>{sister.status}</Badge>
        <Text size="xs" c="dimmed" className="mono">#{sister.id}</Text>
      </Stack>
    </Paper>)}
  </div>;
}
