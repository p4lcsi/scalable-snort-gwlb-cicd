#!/bin/sh
echo "Snort container started"
exec /bin/supervisord -c /supervisord.conf --nodaemon