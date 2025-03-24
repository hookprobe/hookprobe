#!/bin/bash

source network-config.sh

# --- BackUp SQL Database on local disk, or customize for an external drive, or other server infrastructure
echo "Backing UP existing SQL podman volume data to local system or drive."

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

# --- Take backup of the database
podman exec $DB_CONTAINER_NAME sh -c "pg_dump -U $DB_USER $DB_NAME > $BACKUP_FILE"

# --- Copy the backup file to local machine
podman cp $DB_CONTAINER_NAME:$BACKUP_FILE $BACKUP_DIR/$BACKUP_FILE

# Start all the application containers
for container in $DB_CONTAINERS; do
  podman container start $container
done

echo "Back UP Complete for ${TIMESTAMP}. "
