#!/usr/bin/env python2

import socket, os, imp, sys, errno, signal
import rpc_pb2 as rpc
import argparse

MAX_MSG_SIZE = 1024

parser = argparse.ArgumentParser(description="Test --remote option using CRIU RPC")
parser.add_argument('socket', type = str, help = "CRIU service socket")
parser.add_argument('dir', type = str, help = "Directory where CRIU images should be placed")
parser.add_argument('pid', type = int, help = "PID of process to be dumped")

args = vars(parser.parse_args())

# Connect to RPC socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(args['socket'])

# Open images-dir
dir_fd = os.open(args['dir'], os.O_DIRECTORY)
if dir_fd < 0:
	print "Failed to open dir %s" % args['dir']
	sys.exit(-1)

# Prepare dump request
req = rpc.criu_req()
req.type = rpc.DUMP
req.opts.remote	= True
req.opts.log_level = 4
req.opts.pid = args['pid']
req.opts.images_dir_fd	= dir_fd

# Send dump request
s.send(req.SerializeToString())

# Receive responce
resp	= rpc.criu_resp()
resp.ParseFromString(s.recv(MAX_MSG_SIZE))

# Reconnect to RPC socket
s.close()
s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
s.connect(args['socket'])


if resp.type != rpc.DUMP:
	print 'Unexpected dump msg type'
	sys.exit(-1)
else:
	if resp.success:
		print 'Dump Success'
	else:
		print 'Dump Fail'
		sys.exit(-1)

req			= rpc.criu_req()
req.type		= rpc.RESTORE
req.opts.remote	= True
req.opts.log_level = 4
req.opts.images_dir_fd	= dir_fd

# Send restore request
s.send(req.SerializeToString())

# Receive response
resp		= rpc.criu_resp()
resp.ParseFromString(s.recv(MAX_MSG_SIZE))

# Close RPC socket
s.close()
# Close fd of images dir
os.close(dir_fd)

if resp.type != rpc.RESTORE:
	print 'Unexpected restore msg type'
	sys.exit(-1)
else:
	if resp.success:
		print 'Restore success'
		print "PID of the restored program is %d\n" % (resp.restore.pid)
		# Kill restored process
		os.kill(resp.restore.pid, signal.SIGTERM)
	else:
		print 'Restore fail'
		sys.exit(-1)
