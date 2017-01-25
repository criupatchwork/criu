package phaul

/*
 * Communication description.
 * Memfd is the file descriptor via which criu can
 * transfer memory pages.
 */
type PhaulComm struct {
	Memfd int
}

/*
 * Rpc between PhaulClient and PhaulServer. When client
 * calls anything on this one, the corresponding method
 * should be called on PhaulServer object.
 */
type PhaulRpc interface {
	StartIter() error
	StopIter() error
}
