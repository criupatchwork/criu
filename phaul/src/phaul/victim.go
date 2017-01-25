package phaul

import (
	"criu"
)

/*
 * Interface describing what we migrate.
 * Methods:
 *
 * - GetRootPid() returns the pid of the subtree root
 *
 * - DumpCopyRestore() is called on client side when the
 *   pre-iterations are over and it's time to do full dump,
 *   copy images and restore them on the server side.
 *   All the time this method is executed victim tree is
 *   frozen on client. Returning nil kills the tree, error
 *   unfreezes it and resumes. The criu argument is the
 *   pointer on created criu.Criu object on which client
 *   may call Dump(). The requirement on opts passed are:
 *          set Ps.Fd to comm.Memfd
 *          set ParentImg to last_client_images_path
 *          set TrackMem to true
 */
type PhaulVictim interface {
	GetRootPid() int
	DumpCopyRestore(criu *criu.Criu, comm PhaulComm, last_client_images_path string) error
}
