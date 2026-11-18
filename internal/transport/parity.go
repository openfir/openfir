// Package transport contains the interleaved XOR code used on OpenFIR's UDP paths.
package transport

const (
	Stride  = 5
	Members = 4
	Window  = Stride * Members
)

func XOR(dst, src []byte) {
	for i, b := range src {
		dst[i] ^= b
	}
}

// Member gives the position of one symbol in a full interleaved window.
func Member(group, member int) int { return group + member*Stride }

// Path rotates successive wire packets over the available UDP endpoints.
func Path(sequence uint64, count int) int { return int(sequence % uint64(count)) }
