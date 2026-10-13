-- Baseline KumoMTA policy for the comparison: accept from the private bench network and deliver everything to the sink.
-- Written from the KumoMTA documentation, NOT run: check the option names against the KumoMTA version you pin (see bench/compare/compose.yaml).
local kumo = require 'kumo'

-- true = fsync the spool on every write (the durable result); KumoMTA's own default is false.
local flush = os.getenv 'KUMO_SPOOL_FLUSH' == 'true'

kumo.on('init', function()
  kumo.define_spool {
    name = 'data',
    path = '/var/spool/kumomta/data',
    flush = flush,
  }
  kumo.define_spool {
    name = 'meta',
    path = '/var/spool/kumomta/meta',
    flush = flush,
  }

  kumo.configure_local_logs {
    log_dir = '/var/log/kumomta',
    max_segment_duration = '10 seconds',
  }

  kumo.start_esmtp_listener {
    listen = '0.0.0.0:25',
    relay_hosts = { '172.31.7.0/24' },
    max_messages_per_connection = 1000000,
  }
  kumo.start_http_listener { listen = '0.0.0.0:8000', trusted_hosts = { '127.0.0.1' } }
end)

-- Every queue delivers to the sink at its fixed address (no DNS, like the Postfix baseline).
kumo.on('get_queue_config', function(domain, tenant, campaign, routing_domain)
  return kumo.make_queue_config {
    protocol = {
      smtp = {
        mx_list = { '172.31.7.20' },
      },
    },
  }
end)

kumo.on('get_egress_path_config', function(domain, egress_source, site_name)
  return kumo.make_egress_path {
    enable_tls = 'Disabled',
    smtp_port = 2525,
    connection_limit = 64,
    max_message_rate = '100000000/min',
    max_deliveries_per_connection = 10000,
  }
end)

kumo.on('smtp_server_message_received', function(msg)
  -- nothing: accept as is
end)
