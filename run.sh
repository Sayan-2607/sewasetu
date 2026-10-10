#!/bin/sh
# Loads .env if present, then starts the portal.
[ -f .env ] && export $(grep -v '^#' .env | xargs)
exec go run .
