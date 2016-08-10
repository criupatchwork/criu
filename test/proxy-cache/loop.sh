#!/bin/bash

echo $$ > $1.int
mv $1.int $1

while :; do
	sleep 1
done
