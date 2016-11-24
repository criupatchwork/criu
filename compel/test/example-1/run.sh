#!/bin/sh

set -x
donor=$1
modifier=$2
file=$3
value=$4

$donor $file $value &
sleep 1
$modifier $file $value
