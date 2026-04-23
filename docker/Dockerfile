FROM mysql:8.0.40

# Drop in our server config (binlog + SSL enforcement)
COPY my.cnf /etc/mysql/conf.d/custom.cnf

# Init scripts run in alphabetical order on first start.
# MySQL auto-generates TLS certs *before* running /docker-entrypoint-initdb.d/*.sql,
# so by the time init.sql executes, require_secure_transport is already satisfied.
COPY init.sql /docker-entrypoint-initdb.d/01-init.sql

ENV MYSQL_ROOT_PASSWORD=rootpass

EXPOSE 3306
