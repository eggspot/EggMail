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
const InboundMessages = lazy(() => import('./pages/InboundMessages'));
const InboundMessageDetail = lazy(() => import('./pages/InboundMessageDetail'));
const DomainInbound = lazy(() => import('./pages/DomainInbound'));
const Webhooks = lazy(() => import('./pages/Webhooks'));
const Suppressions = lazy(() => import('./pages/Suppressions'));
const Credentials = lazy(() => import('./pages/Credentials'));
const Statistics = lazy(() => import('./pages/Statistics'));
const Settings = lazy(() => import('./pages/Settings'));
const Account = lazy(() => import('./pages/Account'));
const Tenants = lazy(() => import('./pages/admin/Tenants'));
const Users = lazy(() => import('./pages/admin/Users'));
const Status = lazy(() => import('./pages/admin/Status'));
const Certificates = lazy(() => import('./pages/admin/Certificates'));
const StorageSwitch = lazy(() => import('./pages/admin/StorageSwitch'));
const RelayRoutes = lazy(() => import('./pages/admin/RelayRoutes'));
const TlsPolicies = lazy(() => import('./pages/admin/TlsPolicies'));

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
/** An administrator who has not chosen a tenant yet (a fresh install has none) gets guidance instead of "X-Tenant-Id required" errors. */
function NeedsTenant({ children }: { children: ComponentChildren }) {
  const { isAdmin, tenantId, tenants } = useApp();
  if (isAdmin && !tenantId) {
    return (
      <EmptyState title={tenants.length === 0 ? 'Create a tenant first' : 'Choose a tenant'}>
        <p>
          {tenants.length === 0
            ? 'Nothing here is set up yet: every domain, key and message belongs to a tenant.'
            : 'Pick a tenant in the header to see its data.'}{' '}
          <a href="/admin/tenants">Open the tenants page</a>.
        </p>
      </EmptyState>
    );
  }
  return <>{children}</>;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const tenantRoute = (C: ComponentType<any>) => (props: Record<string, unknown>) => (
  <NeedsTenant>
    <C {...props} />
  </NeedsTenant>
);
const OverviewPage = tenantRoute(Overview);
const MessagesPage = tenantRoute(Messages);
const MessageDetailPage = tenantRoute(MessageDetail);
const SendPage = tenantRoute(Send);
const DomainsPage = tenantRoute(Domains);
const DomainDetailPage = tenantRoute(DomainDetail);
const InboundMessagesPage = tenantRoute(InboundMessages);
const InboundMessageDetailPage = tenantRoute(InboundMessageDetail);
const DomainInboundPage = tenantRoute(DomainInbound);
const WebhooksPage = tenantRoute(Webhooks);
const SuppressionsPage = tenantRoute(Suppressions);
const CredentialsPage = tenantRoute(Credentials);
const StatisticsPage = tenantRoute(Statistics);
const SettingsPage = tenantRoute(Settings);
const TenantsPage = adminRoute(Tenants);
const UsersPage = adminRoute(Users);
const StatusPage = adminRoute(Status);
const CertificatesPage = adminRoute(Certificates);
const StoragePage = adminRoute(StorageSwitch);
const RelayRoutesPage = adminRoute(RelayRoutes);
const TlsPoliciesPage = adminRoute(TlsPolicies);

function Routes() {
  const { path } = useLocation();
  const { tenantId, me } = useApp();
  // A temporary password (the generated one of the first administrator) allows the password change and nothing else: that is the only page.
  if (me?.mustChangePassword) {
    return (
      <ErrorBoundary resetKey="password">
        <IsoErrorBoundary>
          <Account />
        </IsoErrorBoundary>
      </ErrorBoundary>
    );
  }
  return (
    // Remount on tenant change so every page reloads its data for the newly selected tenant.
    <ErrorBoundary resetKey={path}>
      <IsoErrorBoundary>
          <Router key={tenantId ?? 'none'}>
            <Route path="/" component={OverviewPage} />
            <Route path="/messages" component={MessagesPage} />
            <Route path="/messages/:id" component={MessageDetailPage} />
            <Route path="/send" component={SendPage} />
            <Route path="/domains" component={DomainsPage} />
            <Route path="/domains/:id" component={DomainDetailPage} />
            <Route path="/domains/:id/inbound" component={DomainInboundPage} />
            <Route path="/inbound" component={InboundMessagesPage} />
            <Route path="/inbound/messages/:id" component={InboundMessageDetailPage} />
            <Route path="/webhooks" component={WebhooksPage} />
            <Route path="/suppressions" component={SuppressionsPage} />
            <Route path="/credentials" component={CredentialsPage} />
            <Route path="/statistics" component={StatisticsPage} />
            <Route path="/settings" component={SettingsPage} />
            <Route path="/account" component={Account} />
            <Route path="/admin/tenants" component={TenantsPage} />
            <Route path="/admin/users" component={UsersPage} />
            <Route path="/admin/status" component={StatusPage} />
            <Route path="/admin/certificates" component={CertificatesPage} />
            <Route path="/admin/storage" component={StoragePage} />
            <Route path="/admin/relay-routes" component={RelayRoutesPage} />
            <Route path="/admin/tls-policies" component={TlsPoliciesPage} />
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
