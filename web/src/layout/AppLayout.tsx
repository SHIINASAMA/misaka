import { AppShell, Avatar, Box, Burger, Group, NavLink, ScrollArea, Stack, Text, ThemeIcon, Title } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { IconActivity, IconCpu, IconNetwork, IconSettings, IconTopologyStar3 } from "@tabler/icons-react";
import { NavLink as RouterNavLink, Outlet, useLocation } from "react-router";

const navItems = [
  { to: "/", label: "Overview", icon: IconActivity },
  { to: "/sisters", label: "Sisters", icon: IconNetwork },
  { to: "/connections", label: "Connections", icon: IconTopologyStar3 },
  { to: "/settings", label: "Settings", icon: IconSettings },
];

export function AppLayout() {
  const [opened, { toggle, close }] = useDisclosure();
  const location = useLocation();
  return <AppShell className="app-shell" header={{ height: 68 }} navbar={{ width: 250, breakpoint: "sm", collapsed: { mobile: !opened } }}>
    <AppShell.Header bg="#0b1020" style={{ borderBottomColor: "rgba(255,255,255,.08)" }}>
      <Group h="100%" px="lg" justify="space-between">
        <Group gap="sm"><Burger opened={opened} onClick={toggle} hiddenFrom="sm" size="sm" color="#67e8f9" /><ThemeIcon variant="gradient" gradient={{ from: "cyan.4", to: "violet.6", deg: 135 }} size={34} radius="md"><IconCpu size={19} /></ThemeIcon><div><Title order={4} lh={1}>Misaka</Title><Text size="xs" c="dimmed" className="mono">SISTER CONSOLE</Text></div></Group>
        <Group gap="xs" visibleFrom="sm"><Avatar size="sm" color="cyan" radius="xl">M</Avatar><Text size="sm" c="dimmed">Local Network</Text></Group>
      </Group>
    </AppShell.Header>
    <AppShell.Navbar p="md" bg="rgba(11,16,32,.82)" style={{ borderRightColor: "rgba(255,255,255,.08)" }}>
      <AppShell.Section grow component={ScrollArea}>
        <Text className="eyebrow" mb="sm" px="sm">Navigation</Text>
        <Stack gap={5}>{navItems.map(({ to, label, icon: Icon }) => <NavLink key={to} component={RouterNavLink} to={to} label={label} leftSection={<Icon size={18} stroke={1.7} />} active={to === "/" ? location.pathname === "/" : location.pathname.startsWith(to)} onClick={close} variant="light" color="cyan" />)}</Stack>
      </AppShell.Section>
      <AppShell.Section><Box px="sm" pt="md" style={{ borderTop: "1px solid rgba(255,255,255,.08)" }}><Text size="xs" c="dimmed">Backend</Text><Text size="sm" className="mono" c="cyan.3">127.0.0.1:31702</Text><Text size="xs" c="dimmed" mt={4}>Local-only API</Text></Box></AppShell.Section>
    </AppShell.Navbar>
    <AppShell.Main><Box className="page-content" px={{ base: "md", sm: "xl" }} py={{ base: "lg", sm: "xl" }}><Outlet /></Box></AppShell.Main>
  </AppShell>;
}
