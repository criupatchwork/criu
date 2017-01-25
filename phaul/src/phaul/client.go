package phaul

import (
	"criu"
	"fmt"
	"github.com/golang/protobuf/proto"
	"rpc"
	"stats"
)

const minPagesWritten uint64 = 64
const maxIters int = 8
const maxGrowDelta int64 = 32

type PhaulClient struct {
	victim PhaulVictim
	phrpc  PhaulRpc
	comm   PhaulComm
}

/*
 * Main entry point. Caller should create the client object by
 * passing here victim, rpc and comm. See comment in corresponding
 * interfaces/structs for explanation.
 *
 * Then call client.Migrate() and enjoy :)
 */
func MakePhaulClient(v PhaulVictim, rpc PhaulRpc, comm PhaulComm) (*PhaulClient, error) {
	return &PhaulClient{victim: v, phrpc: rpc, comm: comm}, nil
}

func isLastIter(iter int, stats *stats.DumpStatsEntry, prev_stats *stats.DumpStatsEntry) bool {
	if iter >= maxIters {
		fmt.Printf("`- max iters reached\n")
		return true
	}

	pagesWritten := stats.GetPagesWritten()
	if pagesWritten < minPagesWritten {
		fmt.Printf("`- tiny pre-dump (%d) reached\n", int(pagesWritten))
		return true
	}

	pages_delta := int64(pagesWritten) - int64(prev_stats.GetPagesWritten())
	if pages_delta >= maxGrowDelta {
		fmt.Printf("`- grow iter (%d) reached\n", int(pages_delta))
		return true
	}

	return false
}

func (pc *PhaulClient) Migrate() error {
	criu := criu.MakeCriu()
	psi := rpc.CriuPageServerInfo{
		Fd: proto.Int32(int32(pc.comm.Memfd)),
	}
	opts := rpc.CriuOpts{
		Pid:      proto.Int32(int32(pc.victim.GetRootPid())),
		LogLevel: proto.Int32(4),
		LogFile:  proto.String("pre-dump.log"),
		Ps:       &psi,
	}

	err := criu.Prepare()
	if err != nil {
		return err
	}

	defer criu.Cleanup()

	imgs, err := preparePhaulImages("c")
	if err != nil {
		return err
	}
	prev_stats := &stats.DumpStatsEntry{}
	iter := 0

	for {
		err = pc.phrpc.StartIter()
		if err != nil {
			return err
		}

		prev_p := imgs.lastImagesDir()
		img_dir, err := imgs.openNextDir()
		if err != nil {
			return err
		}

		opts.ImagesDirFd = proto.Int32(int32(img_dir.Fd()))
		if prev_p != "" {
			opts.ParentImg = proto.String(prev_p)
		}

		err = criu.PreDump(opts, nil)
		img_dir.Close()
		if err != nil {
			return err
		}

		err = pc.phrpc.StopIter()
		if err != nil {
			return err
		}

		st, err := criuGetDumpStats(img_dir)
		if err != nil {
			return err
		}

		if isLastIter(iter, st, prev_stats) {
			break
		}

		prev_stats = st
	}

	err = pc.phrpc.StartIter()
	if err == nil {
		prev_p := imgs.lastImagesDir()
		err = pc.victim.DumpCopyRestore(criu, pc.comm, prev_p)
		err2 := pc.phrpc.StopIter()
		if err == nil {
			err = err2
		}
	}

	return err
}
