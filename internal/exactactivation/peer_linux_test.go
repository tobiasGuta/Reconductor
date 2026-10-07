//go:build linux

package exactactivation

import (
	"errors"
	"testing"
)

func TestPeerCredentials(t *testing.T) {
	identity := peerIdentity{uid: 10001, gid: 10002}
	for _, groups := range [][]int{nil, {}, {10002}, {10002, 10002}} {
		if err := verifyPeerCredentials(identity, processCredentials{uid: 10001, gid: 10002, groups: groups}); err != nil {
			t.Fatalf("primary-only groups rejected: %v", err)
		}
	}
	for _, c := range []processCredentials{
		{uid: 10000, gid: 10002}, {uid: 10001, gid: 10000},
		{uid: 10001, gid: 10002, groups: []int{10002, 10}},  // e.g. wheel
		{uid: 10001, gid: 10002, groups: []int{10002, 999}}, // e.g. docker
		{uid: 10001, gid: 10002, groups: []int{10002, 0}},
		{uid: 10001, gid: 10002, groups: []int{10003}}, // any unrelated GID
		{uid: -1, gid: 10002}, {uid: 10001, gid: -1},
		{uid: 10001, gid: 10002, groups: []int{-1}},
	} {
		if !errors.Is(verifyPeerCredentials(identity, c), ErrPeerCredentials) {
			t.Fatalf("accepted unexpected credentials: %+v", c)
		}
	}
	for _, id := range []peerIdentity{{uid: 0, gid: 10002}, {uid: 10001, gid: 0}, {}} {
		if !errors.Is(verifyPeerCredentials(id, processCredentials{uid: int(id.uid), gid: int(id.gid)}), ErrPeerCredentials) {
			t.Fatal("accepted root/zero expected identity")
		}
	}
}
