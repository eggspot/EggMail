import { ErrorBoundary as IsoErrorBoundary, LocationProvider, Route, Router, lazy, useLocation } from 'preact-iso';
import type { ComponentChildren, ComponentType } from 'preact';
import { ErrorBoundary } from './components/ErrorBoundary';
import { Layout } from './components/Layout';
import { WarningBanner } from './components/WarningBanner';
import { EmptyState, Loading, Button } from './components/ui';
import { AppProvider, useApp } from './state/app';
import { friendlyMessage } from './api/errorMessages';
import Login from './pages/Login';

// Every page is its own chunk (code splitting by route).
const Overview = lazy(() => import('./pages/Overview'));
const Messages = lazy(() => import('./pages/Messages'));
const MessageDetail = lazy(() => import('./pages/MessageDetail'));
const Send = lazy(() => import('./pages/Send'));
const Domains = lazy(() => import('./pages/Domains'));
const DomainDetail = lazy(() => import('./pages/DomainDetail'));
const Webhooks = lazy(() => import('./pages/Webhooks'));
const Suppressions = lazy(() => import('./pages/Suppressions'));
const Credentials = lazy(() => import('./pages/Credentials'));
const Statistics = lazy(() => import('./pages/Statistics'));
const Settings = lazy(() => import('./pages/Settings'));
const Tenants = lazy(() => import('./pages/admin/Tenants'));
const Status = lazy(() => import('./pages/admin/Status'));
const Certificates = lazy(() => import('./pages/admin/Certificates'));
const StorageSwitch = lazy(() => import('./pages/admin/StorageSwitch'));

function NotFound() {
  return (
    <EmptyState title="Page not found" action={<a href="/">Go to the overview</a>}>
      <p>There is no page at this address.</p>
    </EmptyState>
  );
}

function AdminOnly({ children }: { children: ComponentChildren }) {
  const { isAdmin } = useApp();
  if (!isAdmin) {
    return (
      <EmptyState title="Administrators only">
        <p>This page is only available to administrator accounts.</p>
      </EmptyState>
    );
  }
  return <>{children}</>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const adminRoute = (C: ComponentType<any>) => (props: Record<string, unknown>) => (
  <AdminOnly>
    <C {...props} />
  </AdminOnly>
);
const TenantsPage = adminRoute(Tenants);
const StatusPage = adminRoute(Status);
const CertificatesPage = adminRoute(Certificates);
const StoragePage = adminRoute(StorageSwitch);

function Routes() {
  const { path } = useLocation();
  const { tenantId } = useApp();
  return (
    // Remount on tenant change so every page reloads its data for the newly selected tenant.
    <ErrorBoundary resetKey={path}>
      <IsoErrorBoundary>
          <Router key={tenantId ?? 'none'}>
            <Route path="/" component={Overview} />
            <Route path="/messages" component={Messages} />
            <Route path="/messages/:id" component={MessageDetail} />
            <Route path="/send" component={Send} />
            <Route path="/domains" component={Domains} />
            <Route path="/domains/:id" component={DomainDetail} />
            <Route path="/webhooks" component={Webhooks} />
            <Route path="/suppressions" component={Suppressions} />
            <Route path="/credentials" component={Credentials} />
            <Route path="/statistics" component={Statistics} />
            <Route path="/settings" component={Settings} />
            <Route path="/admin/tenants" component={TenantsPage} />
            <Route path="/admin/status" component={StatusPage} />
            <Route path="/admin/certificates" component={CertificatesPage} />
            <Route path="/admin/storage" component={StoragePage} />
            <Route default component={NotFound} />
          </Router>
      </IsoErrorBoundary>
    </ErrorBoundary>
  );
}

export function OfflineScreen() {
  const { offlineError, retry } = useApp();
  return (
    <div class="login-wrap">
      <WarningBanner />
      <main class="login card" id="main">
        <h1>Server not available</h1>
        <p role="alert">{offlineError ? friendlyMessage(offlineError) : 'The server is not reachable.'}</p>
        <p class="muted">
          {offlineError?.code === 'not_ready'
            ? 'The server answered 503 not_ready: the storage backend is down or still starting. Mail already accepted is not lost.'
            : 'The dashboard keeps no data offline.'}
        </p>
        <Button variant="primary" onClick={retry}>
          Try again
        </Button>
      </main>
    </div>
  );
}

export function Shell() {
  const { status } = useApp();
  if (status === 'loading') {
    return (
      <div class="login-wrap">
        <Loading label="Connecting to the server" />
      </div>
    );
  }
  if (status === 'offline') return <OfflineScreen />;
  if (status === 'anonymous') return <Login />;
  return (
    <Layout>
      <Routes />
    </Layout>
  );
}

export function App() {
  return (
    <ErrorBoundary>
      <LocationProvider>
        <AppProvider>
          <Shell />
        </AppProvider>
      </LocationProvider>
    </ErrorBoundary>
  );
}
