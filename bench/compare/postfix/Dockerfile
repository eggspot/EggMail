# Postfix as the baseline: accepts mail from the private bench network and relays everything to the sink. Debian's Postfix with its default
# queue behaviour (queue files are fsynced), so the default result is the DURABLE one.
FROM debian:bookworm-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends postfix \
 && rm -rf /var/lib/apt/lists/*
COPY main.cf /etc/postfix/main.cf
EXPOSE 25
# start-fg runs the master process in the foreground and logs to stdout (maillog_file in main.cf).
CMD ["postfix", "start-fg"]
