FROM geonode/postgis:15-3.5-latest

COPY init-readonly-user.sh /docker-entrypoint-initdb.d/
RUN chmod +x /docker-entrypoint-initdb.d/init-readonly-user.sh