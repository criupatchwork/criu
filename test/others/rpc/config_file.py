#!/usr/bin/python2

import os
import socket
import sys
import rpc_pb2 as rpc
import argparse
import subprocess
from tempfile import mkstemp

log_file = 'config_file_test.log'
does_not_exist = 'does-not.exist'


def setup_swrk():
	print('Connecting to CRIU in swrk mode.')
	css = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
	swrk = subprocess.Popen(['./criu', "swrk", "%d" % css[0].fileno()])
	css[0].close()
	return swrk, css[1]


def setup_config_file(content):
	# Creating a temporary file which will be used as configuration file.
	fd, path = mkstemp()

	with os.fdopen(fd, 'w') as f:
		f.write(content)

	os.environ['CRIU_CONFIG_FILE'] = path

	return path


def cleanup_config_file(path):
	del os.environ['CRIU_CONFIG_FILE']
	os.unlink(path)


def setup_criu_dump_request():
	# Create criu msg, set it's type to dump request
	# and set dump options. Checkout more options in protobuf/rpc.proto
	req = rpc.criu_req()
	req.type = rpc.DUMP
	req.opts.leave_running = True
	req.opts.log_level = 4
	req.opts.log_file = log_file
	req.opts.images_dir_fd = os.open(args['dir'], os.O_DIRECTORY)
	# Not necessary, just for testing
	req.opts.tcp_established = True
	req.opts.shell_job = True
	return req


def do_rpc(s, req):
	# Send request
	s.send(req.SerializeToString())

	# Recv response
	resp = rpc.criu_resp()
	MAX_MSG_SIZE = 1024
	resp.ParseFromString(s.recv(MAX_MSG_SIZE))

	s.close()
	return resp


def test_broken_configuration_file():
	# Testing RPC configuration file mode with a broken configuration file.
	# This should not fail but print a warning
	content = 'hopefully-this-option-will-never=exist'
	path = setup_config_file(content)
	req = setup_criu_dump_request()
	_, s = setup_swrk()
	resp = do_rpc(s, req)
	s.close()
	cleanup_config_file(path)
	check_results(resp, log_file)
	search_in_log_file(log_file, 'Unknown option encountered')


def search_in_log_file(log, message):
	with open(os.path.join(args['dir'], log)) as f:
		if message not in f.read():
			print('FAIL: Missing the expected error message (%s) in the log file' % message)
			sys.exit(-1)


def check_results(resp, log):
	# Check if the specified log file exists
	if not os.path.isfile(os.path.join(args['dir'], log)):
		print('FAIL: Expected log file %s does not exist' % log)
		sys.exit(-1)
	# Dump should have failed with: 'The criu itself is within dumped tree'
	if resp.type != rpc.DUMP:
		print('FAIL: Unexpected msg type %r' % resp.type)
		sys.exit(-1)
	if 'The criu itself is within dumped tree' not in resp.cr_errmsg:
		print('FAIL: Missing the expected error message in RPC response')
		sys.exit(-1)
	# Look into the log file for the same message
	search_in_log_file(log, 'The criu itself is within dumped tree')


def test_rpc_without_configuration_file():
	# Testing without configuration file
	# Just doing a dump and checking for the logfile
	req = setup_criu_dump_request()
	_, s = setup_swrk()
	resp = do_rpc(s, req)
	s.close()
	check_results(resp, log_file)


def test_rpc_with_configuration_file():
	# Testing with configuration file
	# Just doing a dump and checking for the logfile

	# Setting a different log file via configuration file
	# This should not work as RPC settings overwrite configuration
	# file settings in the default configuration.
	log = does_not_exist
	content = 'log-file ' + log + '\n'
	content += 'no-tcp-established\nno-shell-job'
	path = setup_config_file(content)
	req = setup_criu_dump_request()
	_, s = setup_swrk()
	do_rpc(s, req)
	s.close()
	cleanup_config_file(path)
	# Check if the specified log file exists
	# It should not as configuration files do not overwrite RPC values.
	if os.path.isfile(os.path.join(args['dir'], log)):
		print('FAIL: log file %s should not exist' % log)
		sys.exit(-1)


def test_rpc_with_configuration_file_overwriting_rpc():
	# Testing with configuration file
	# Just doing a dump and checking for the logfile

	# Setting a different log file via configuration file
	# This should not work as RPC settings overwrite configuration
	# file settings in the default configuration.
	log = does_not_exist
	content = 'log-file ' + log + '\n'
	content += 'no-tcp-established\nno-shell-job'
	path = setup_config_file(content)
	req = setup_criu_dump_request()
	req.opts.config_file = path
	_, s = setup_swrk()
	resp = do_rpc(s, req)
	s.close()
	cleanup_config_file(path)
	check_results(resp, log)


parser = argparse.ArgumentParser(description="Test config files using CRIU RPC")
parser.add_argument('dir', type = str, help = "Directory where CRIU images should be placed")

args = vars(parser.parse_args())

try:
	# optional cleanup
	os.unlink(os.path.join(args['dir'], does_not_exist))
	os.unlink(os.path.join(args['dir'], log_file))
except OSError:
	pass

test_broken_configuration_file()
test_rpc_without_configuration_file()
test_rpc_with_configuration_file()
test_rpc_with_configuration_file_overwriting_rpc()
