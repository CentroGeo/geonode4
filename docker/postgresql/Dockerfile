ARG PG_READ_ONLY_USERNAME
ARG PG_READ_ONLY_PASSWORD
FROM geonode/postgis:15.3-latest


RUN /bin/sh -c "DO \$\$ \
BEGIN \
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '${PG_READ_ONLY_USERNAME}') THEN \
        CREATE ROLE ${PG_READ_ONLY_USERNAME} WITH LOGIN PASSWORD '${PG_READ_ONLY_PASSWORD}'; \
    END IF; \
END \
\$\$;" | psql -U postgres

RUN psql -U postgres -c "GRANT pg_read_all_data TO ${PG_READ_ONLY_USERNAME};"