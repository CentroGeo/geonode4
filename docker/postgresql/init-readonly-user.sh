#!/bin/bash
set -e

# Wait until PostgreSQL is ready
until pg_isready -U postgres; do
  echo "Waiting for PostgreSQL..."
  sleep 2
done

# Create the user if it doesn't exist
psql -v ON_ERROR_STOP=1 --username "postgres" <<-EOSQL
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${PG_READ_ONLY_USERNAME}') THEN
    CREATE ROLE ${PG_READ_ONLY_USERNAME} WITH LOGIN PASSWORD '${PG_READ_ONLY_PASSWORD}';
  END IF;
END
\$\$;

GRANT pg_read_all_data TO ${PG_READ_ONLY_USERNAME};
EOSQL