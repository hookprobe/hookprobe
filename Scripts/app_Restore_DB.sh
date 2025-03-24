#!/bin/bash

source network-config.sh

# --- RestoreSQL Database from local disk, or customize for an external drive, or other server infrastructure
echo "Restore existing SQL podman volume data from local system or drive."

# --- Create a timestamp for the backup file
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

BACKUP_DIR=~/home/myuser/back-ups/app_db
BACKUP_FILE=${TIMESTAMP}.sql

DB_CONTAINERS="$DB_CONTAINER_NAME $DB_CONTAINER_OTHER"

# --- Create backup directory if it doesn't exist
mkdir -p $BACKUP_DIR

# --- Stop all the application containers
for container in $DB_CONTAINERS; do
  podman container stop $container
done

# Create database
podman exec $DB_CONTAINER_NAME createdb -U $DB_USER $DB_NAME

# Copy backup file to container
podman cp $BACKUP_DIR/$BACKUP_FILE $DB_CONTAINER_NAME:$BACKUP_FILE

# Restore database
podman exec $DB_CONTAINER_NAME sh -c "psql -U $DB_USER -d $DB_NAME < $BACKUP_FILE"

# Start all the application containers
for container in $DB_CONTAINERS; do
  podman container start $container
done

echo "Back UP Complete for ${TIMESTAMP}. "
