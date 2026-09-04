import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { AppLayout } from "./layout/AppLayout";
import { ConnectionsPage } from "./pages/ConnectionsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { SettingsPage } from "./pages/SettingsPage";
import { SisterDetailPage } from "./pages/SisterDetailPage";
import { SistersPage } from "./pages/SistersPage";

export function App() { return <BrowserRouter><Routes><Route element={<AppLayout />}><Route index element={<OverviewPage />} /><Route path="sisters" element={<SistersPage />} /><Route path="sisters/:id" element={<SisterDetailPage />} /><Route path="connections" element={<ConnectionsPage />} /><Route path="settings" element={<SettingsPage />} /><Route path="*" element={<Navigate to="/" replace />} /></Route></Routes></BrowserRouter>; }
