#!/bin/bash

ruff check ./meter_reading.py --verbose
if [[ $? -ne 0 ]]; then
  exit 1
fi

# Find old images
for i in `docker images --filter 'reference=utdrmac/elecmeter' --format '{{.ID}}'`; do
  echo "Removing $i"
  docker rmi $i
done

# Incr version
NEXTVERSION=$(cat VERSION | awk -F. -v OFS=. '{$NF += 1 ; print}')
echo $NEXTVERSION >VERSION

docker build -t utdrmac/elecmeter:${NEXTVERSION} .
