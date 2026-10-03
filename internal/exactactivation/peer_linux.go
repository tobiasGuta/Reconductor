//go:build linux

package exactactivation

import (
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"
)

type peerIdentity struct{ uid, gid uint32 }
type processCredentials struct {
	uid, gid int
	groups   []int
}

func resolvePeerIdentity() (peerIdentity, error) {
	account, err := user.Lookup(PeerUser)
	if err != nil {
		return peerIdentity{}, ErrPeerCredentials
	}
	group, err := user.LookupGroup(PeerGroup)
	if err != nil {
		return peerIdentity{}, ErrPeerCredentials
	}
	uid, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || uid == 0 {
		return peerIdentity{}, ErrPeerCredentials
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil || gid == 0 || account.Gid != group.Gid {
		return peerIdentity{}, ErrPeerCredentials
	}
	return peerIdentity{uid: uint32(uid), gid: uint32(gid)}, nil
}

// VerifyPeerCredentials resolves the fixed account and inspects actual effective
// UID/GID and getgroups(), rather than trusting User=/Group= configuration text.
// Provisioning of locked login, account ownership and service exclusivity must
// be established independently. This is not a containment/capability preflight.
func VerifyPeerCredentials() error {
	identity, err := resolvePeerIdentity()
	if err != nil {
		return err
	}
	groups, err := unix.Getgroups()
	if err != nil {
		return ErrPeerCredentials
	}
	return verifyPeerCredentials(identity, processCredentials{uid: os.Geteuid(), gid: os.Getegid(), groups: groups})
}

func verifyPeerCredentials(identity peerIdentity, credentials processCredentials) error {
	if identity.uid == 0 || identity.gid == 0 || credentials.uid < 0 || credentials.gid < 0 || uint64(credentials.uid) != uint64(identity.uid) || uint64(credentials.gid) != uint64(identity.gid) {
		return ErrPeerCredentials
	}
	for _, group := range credentials.groups {
		// Linux may include the primary GID in getgroups(). Repeated occurrences
		// add no authority; every different numeric GID is rejected, including 0.
		if group < 0 || uint64(group) != uint64(identity.gid) {
			return ErrPeerCredentials
		}
	}
	return nil
}
