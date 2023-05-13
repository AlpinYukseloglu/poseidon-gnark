package circuits

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// TestPoseidon tests the Gnark Poseidon implementation against Iden3's Go implementation on all the test
// vectors outlined in the original paper's reference repository, which can be found here: https://extgit.iaik.tugraz.at/krypto/hadeshash/-/tree/master/code
//
// The actual test vectors are outlined here: https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/test_vectors.txt
// We have included more for the sake of robustness.
// Note that our implementation is focused on the 3-input variant with an x^5 S-box, so not all the test vectors apply.
func TestPoseidon(t *testing.T) {
	tests := map[string]struct {
		gnarkPoseidonInput     [3]frontend.Variable
		referencePoseidonInput []*big.Int
	}{
		"happy path: basic input": {
			gnarkPoseidonInput:     [3]frontend.Variable{1, 2, 3},
			referencePoseidonInput: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
		},
		"official test vector: poseidonperm_x5_254_3": {
			gnarkPoseidonInput:     [3]frontend.Variable{0, 1, 2},
			referencePoseidonInput: []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2)},
		},
		"zero vector": {
			gnarkPoseidonInput:     [3]frontend.Variable{0, 0, 0},
			referencePoseidonInput: []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		},
		"larger inputs": {
			gnarkPoseidonInput:     [3]frontend.Variable{129048, 990217, 2234383333},
			referencePoseidonInput: []*big.Int{big.NewInt(129048), big.NewInt(990217), big.NewInt(2234383333)},
		},
		"decreasing vector inputs": {
			gnarkPoseidonInput:     [3]frontend.Variable{10000000, 10000, 100},
			referencePoseidonInput: []*big.Int{big.NewInt(10000000), big.NewInt(10000), big.NewInt(100)},
		},
	}

	for name, testCase := range tests {

		assert := test.NewAssert(t)
		var circuit circuitPoseidon

		// Compute reference hash to test against
		referenceHash, err := poseidon.Hash(testCase.referencePoseidonInput)
		if err != nil {
			t.Fatal(err, "Failed to compute reference poseidon hash for test case: ", name)
		}
		t.Logf("Reference hash: %s", referenceHash.String())

		// Generate poseidon hash using gnark implementation
		assert.ProverSucceeded(&circuit, &circuitPoseidon{
			A:    testCase.gnarkPoseidonInput,
			Hash: referenceHash,
		}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))

		// Ensure output correctly compiles
		_r1cs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal(err, "Failed to compile computed poseidon hash for test case: ", name)
		}

		// Sanity check and debugging support for internal variables
		internal, secret, public := _r1cs.GetNbVariables()
		t.Logf("Public, secret, internal %v, %v, %v\n", public, secret, internal)
	}
}

// --- Test Helpers ---

type circuitPoseidon struct {
	A    [3]frontend.Variable `gnark:",public"`
	Hash frontend.Variable    `gnark:",public"`
}

func (t *circuitPoseidon) Define(api frontend.API) error {
	hash := Poseidon(api, t.A[:])
	api.Println(t.Hash)
	api.Println(hash)
	api.AssertIsEqual(hash, t.Hash)
	return nil
}
