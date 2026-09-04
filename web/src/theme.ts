import { createTheme, rem } from "@mantine/core";

export const theme = createTheme({
  primaryColor: "cyan",
  primaryShade: 4,
  fontFamily: "Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, sans-serif",
  headings: {
    fontFamily: "Space Grotesk, Inter, ui-sans-serif, system-ui, sans-serif",
    fontWeight: "650",
  },
  fontFamilyMonospace: "SFMono-Regular, Consolas, Liberation Mono, monospace",
  defaultRadius: "md",
  spacing: { xs: rem(8), sm: rem(12), md: rem(18), lg: rem(26), xl: rem(36) },
  colors: {
    cyan: ["#ecfeff", "#cffafe", "#a5f3fc", "#67e8f9", "#22d3ee", "#06b6d4", "#0891b2", "#0e7490", "#155e75", "#164e63"],
    violet: ["#f5f3ff", "#ede9fe", "#ddd6fe", "#c4b5fd", "#a78bfa", "#8b5cf6", "#7c3aed", "#6d28d9", "#5b21b6", "#4c1d95"],
  },
});
