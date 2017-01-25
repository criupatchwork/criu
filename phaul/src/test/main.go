package main

import (
	"criu"
	"fmt"
	"github.com/golang/protobuf/proto"
	"os"
	"phaul"
	"rpc"
	"strconv"
	"strings"
	"syscall"
)

type testVictim struct {
	criu.CriuNoNotify
	pid int
	srv *phaul.PhaulServer
}

func (v testVictim) GetRootPid() int {
	return v.pid
}

/* Dir where test will put dump images */
const images_dir = "test_images"

func mergeImages(dump_dir, last_pre_dump_dir string) error {
	idir, err := os.Open(dump_dir)
	if err != nil {
		return err
	}

	defer idir.Close()

	imgs, err := idir.Readdirnames(0)
	if err != nil {
		return err
	}

	for _, fname := range imgs {
		if !strings.HasSuffix(fname, ".img") {
			continue
		}

		fmt.Printf("\t%s -> %s/\n", fname, last_pre_dump_dir)
		err = syscall.Link(dump_dir+"/"+fname, last_pre_dump_dir+"/"+fname)
		if err != nil {
			return err
		}
	}

	return nil
}

func (v testVictim) PostDump() error {
	last_srv_images_dir := v.srv.LastImagesDir()
	/*
	 * In images_dir we have images from dump, in the
	 * last_srv_images_dir -- where server-side images
	 * (from page server, with pages and pagemaps) are.
	 * Need to put former into latter and restore from
	 * them.
	 */
	err := mergeImages(images_dir, last_srv_images_dir)
	if err != nil {
		return err
	}

	cr := criu.MakeCriu()
	opts := rpc.CriuOpts{
		LogLevel: proto.Int32(4),
		LogFile:  proto.String("restore.log"),
	}
	img_dir, err := os.Open(last_srv_images_dir)
	if err != nil {
		return err
	}
	defer img_dir.Close()

	opts.ImagesDirFd = proto.Int32(int32(img_dir.Fd()))

	fmt.Printf("Do restore\n")
	return cr.Restore(opts, nil)
}

func (v testVictim) DumpCopyRestore(cr *criu.Criu, comm phaul.PhaulComm, last_client_images_dir string) error {
	fmt.Printf("Final stage\n")
	psi := rpc.CriuPageServerInfo{
		Fd: proto.Int32(int32(comm.Memfd)),
	}
	opts := rpc.CriuOpts{
		Pid:      proto.Int32(int32(v.pid)),
		LogLevel: proto.Int32(4),
		LogFile:  proto.String("dump.log"),
		Ps:       &psi,
		TrackMem: proto.Bool(true),
	}

	err := os.Mkdir(images_dir, 0700)
	if err != nil {
		return err
	}

	img_dir, err := os.Open(images_dir)
	if err != nil {
		return err
	}
	defer img_dir.Close()

	opts.ImagesDirFd = proto.Int32(int32(img_dir.Fd()))
	opts.ParentImg = proto.String(last_client_images_dir)

	fmt.Printf("Do dump\n")
	return cr.Dump(opts, v)
}

func main() {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Printf("Can't make socketpair\n")
		return
	}

	fmt.Printf("Make server part (socket %d)\n", fds[1])
	srv, err := phaul.MakePhaulServer(phaul.PhaulComm{Memfd: fds[1]})
	if err != nil {
		return
	}

	fmt.Printf("Make client part (socket %d)\n", fds[0])
	pid, _ := strconv.Atoi(os.Args[1])
	cln, err := phaul.MakePhaulClient(testVictim{pid: pid, srv: srv},
		srv, phaul.PhaulComm{Memfd: fds[0]})
	if err != nil {
		return
	}

	fmt.Printf("Migrate\n")
	err = cln.Migrate()
	if err != nil {
		fmt.Printf("Failed: ")
		fmt.Print(err)
		return
	}

	fmt.Printf("SUCCESS!\n")
}
