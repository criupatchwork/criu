# Check gc for link remaps and locked tcp connections
set -e
source `dirname $0`/criu-lib.sh
prep

./test/zdtm.py run -t zdtm/static/unlink_regular00 --gc || fail
./test/zdtm.py run -t zdtm/static/mntns_link_remap --gc || fail

./test/zdtm.py run -t zdtm/static/socket-tcp --gc || fail
./test/zdtm.py run -t zdtm/static/socket-tcp6 --gc || fail
