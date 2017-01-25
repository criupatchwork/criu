package phaul

import (
	"criu"
	"fmt"
	"github.com/golang/protobuf/proto"
	"rpc"
)

type PhaulServer struct {
	comm PhaulComm
	imgs *images
	cr   *criu.Criu
}

/*
 * Main entry point. Make the server with comm and call PhaulRpc
 * methods on it upon client requests.
 */
func MakePhaulServer(comm PhaulComm) (*PhaulServer, error) {
	img, err := preparePhaulImages("s")
	if err != nil {
		return nil, err
	}

	cr := criu.MakeCriu()

	return &PhaulServer{imgs: img, comm: comm, cr: cr}, nil
}

/*
 * PhaulRpc methods
 */
func (s *PhaulServer) StartIter() error {
	fmt.Printf("S: start iter\n")
	psi := rpc.CriuPageServerInfo{
		Fd: proto.Int32(int32(s.comm.Memfd)),
	}
	opts := rpc.CriuOpts{
		LogLevel: proto.Int32(4),
		LogFile:  proto.String("ps.log"),
		Ps:       &psi,
	}

	prev_p := s.imgs.lastImagesDir()
	img_dir, err := s.imgs.openNextDir()
	if err != nil {
		return err
	}
	defer img_dir.Close()

	opts.ImagesDirFd = proto.Int32(int32(img_dir.Fd()))
	if prev_p != "" {
		opts.ParentImg = proto.String(prev_p)
	}

	return s.cr.StartPageServer(opts)
}

func (s *PhaulServer) StopIter() error {
	return nil
}

/*
 * Server-local methods
 */
func (s PhaulServer) LastImagesDir() string {
	return s.imgs.lastImagesDir()
}
