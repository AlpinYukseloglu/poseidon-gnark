package circuits

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// QuinticSBox implements the quintic S-box transformation (x^5)
func QuinticSBox(api frontend.API, in frontend.Variable) frontend.Variable {
	in2 := api.Mul(in, in)   // square the input (x^2)
	in4 := api.Mul(in2, in2) // square the result (x^4)
	return api.Mul(in4, in)  // multiply by the input (x^5)
}

// PoseidonCfg encapsulates the parameters and related functions for the Poseidon hash function
type PoseidonCfg struct {
	T        int
	NRoundsF int
	NRoundsP int
	C        []*big.Int
	M        [][]*big.Int
}

func getNRoundsPC(t int) int {
	// Precomputed values from https://eprint.iacr.org/2019/458.pdf (table 2, table 8)
	nRoundsPC := []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}
	return nRoundsPC[t-2]
}

func getPoseidonC(t int) []*big.Int {
	// Replace this with the actual precomputed constants for your implementation
	// This is a placeholder for demonstration purposes
	return make([]*big.Int, t*(2+2+1+getNRoundsPC(t)))
}

func getPoseidonM(t int) [][]*big.Int {
	// Replace this with the actual precomputed matrix for your implementation
	// This is a placeholder for demonstration purposes
	m := make([][]*big.Int, t)
	for i := range m {
		m[i] = make([]*big.Int, t)
		for j := range m[i] {
			m[i][j] = big.NewInt(1)
		}
	}
	return m
}

// NewPoseidonCfg creates a new PoseidonCfg instance with the given number of inputs (t)
func NewPoseidonCfg(t int) *PoseidonCfg {
	return &PoseidonCfg{
		T:        t,
		NRoundsF: 8,
		NRoundsP: getNRoundsPC(t),
		C:        getPoseidonC(t),
		M:        getPoseidonM(t),
	}
}

// PoseidonInternalState represents the internal state of the Poseidon hash function
type PoseidonInternalState struct {
	api   frontend.API
	state []frontend.Variable
}

// NewPoseidonInternalState creates a new PoseidonInternalState instance with the given initial state and inputs
func NewPoseidonInternalState(api frontend.API, initialState frontend.Variable, inputs []frontend.Variable) *PoseidonInternalState {
	t := len(inputs) + 1
	state := make([]frontend.Variable, t)
	state[0] = initialState
	copy(state[1:], inputs)
	return &PoseidonInternalState{api: api, state: state}
}

// AddRoundConstants method adds round constants to the state
func (cfg *PoseidonCfg) AddRoundConstants(state *PoseidonInternalState, r int) {
	for i, v := range state.state {
		state.state[i] = state.api.Add(v, cfg.C[i+r]) // add the round constant to each element of the state
	}
}

// ApplyMixingLayer method applies the mixing layer (matrix multiplication) to the state
func (cfg *PoseidonCfg) ApplyMixingLayer(state *PoseidonInternalState) {
	t := len(state.state)
	newState := make([]frontend.Variable, t)
	for i := 0; i < t; i++ {
		lc := frontend.Variable(0)
		for j := 0; j < t; j++ {
			lc = state.api.Add(lc, state.api.Mul(cfg.M[j][i], state.state[j])) // linear combination of the state elements and the matrix coefficients
		}
		newState[i] = lc
	}
	state.state = newState
}

// ApplyMixingLayerToLastElement method applies the mixing layer (matrix multiplication) to the last element of the state
func (cfg *PoseidonCfg) ApplyMixingLayerToLastElement(state *PoseidonInternalState, s int) frontend.Variable {
	t := len(state.state)
	out := frontend.Variable(0)
	for j := 0; j < t; j++ {
		out = state.api.Add(out, state.api.Mul(cfg.M[j][s], state.state[j])) // linear combination of the state elements and the matrix coefficients for the last element
	}
	return out
}

// ApplyQuinticSBox method applies the quintic S-box transformation to the i-th element of the state
func (state *PoseidonInternalState) ApplyQuinticSBox(i int) {
	state.state[i] = QuinticSBox(state.api, state.state[i])
}

// ComputePoseidonHashEx computes the Poseidon hash function with the given PoseidonCfg and PoseidonInternalState instances
func ComputePoseidonHashEx(api frontend.API, cfg *PoseidonCfg, state *PoseidonInternalState, nOuts int) ([]frontend.Variable, error) {
	nInputs := len(state.state) - 1
	if nInputs != cfg.T-1 {
		return nil, errors.New("number of inputs does not match the parameters")
	}

	out := make([]frontend.Variable, nOuts)
	nRoundsF := cfg.NRoundsF
	nRoundsP := cfg.NRoundsP

	// Full S-box layer
	cfg.AddRoundConstants(state, 0)
	for r := 0; r < nRoundsF/2-1; r++ {
		for j := 0; j < cfg.T; j++ {
			state.ApplyQuinticSBox(j)
		}
		cfg.AddRoundConstants(state, (r+1)*cfg.T)
		cfg.ApplyMixingLayer(state)
	}

	// Partial S-box layer
	for j := 0; j < cfg.T; j++ {
		state.ApplyQuinticSBox(j)
	}
	cfg.AddRoundConstants(state, nRoundsF/2*cfg.T)

	// Linear layer
	cfg.ApplyMixingLayer(state)

	// Partial S-box layer
	for r := 0; r < nRoundsP; r++ {
		state.ApplyQuinticSBox(0)
		cfg.AddRoundConstants(state, (nRoundsF/2+1)*cfg.T+r)
		cfg.ApplyMixingLayer(state)
	}

	// Full S-box layer
	for r := 0; r < nRoundsF/2-1; r++ {
		for j := 0; j < cfg.T; j++ {
			state.ApplyQuinticSBox(j)
		}
		cfg.AddRoundConstants(state, (nRoundsF/2+1)*cfg.T+nRoundsP+r*cfg.T)
		cfg.ApplyMixingLayer(state)
	}

	// Final output computation
	for i := 0; i < nOuts; i++ {
		out[i] = cfg.ApplyMixingLayerToLastElement(state, i)
	}
	return out, nil
}

// ComputePoseidonHash computes the Poseidon hash function with the given inputs and PoseidonCfg instance
func ComputePoseidonHash(api frontend.API, cfg *PoseidonCfg, inputs []frontend.Variable) (frontend.Variable, error) {
	initialState := frontend.Variable(0)
	state := NewPoseidonInternalState(api, initialState, inputs)
	out, err := ComputePoseidonHashEx(api, cfg, state, 1)
	if err != nil {
		return 0, err
	}
	return out[0], nil
}

func Sigma(api frontend.API, in frontend.Variable) frontend.Variable {
	return api.Mul(in, in, in, in, in)
}

func Ark(api frontend.API, in []frontend.Variable, c []*big.Int, r int) []frontend.Variable {
	out := make([]frontend.Variable, len(in))
	for i := 0; i < len(in); i++ {
		out[i] = api.Add(in[i], c[i+r])
	}
	return out
}

func Mix(api frontend.API, in []frontend.Variable, m [][]*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(in))
	for i := 0; i < len(in); i++ {
		column := getColumn(m, i)
		out[i] = computeLinearCombination(api, in, column)
	}
	return out
}

func getColumn(matrix [][]*big.Int, columnIndex int) []*big.Int {
	column := make([]*big.Int, len(matrix))
	for i := 0; i < len(matrix); i++ {
		column[i] = matrix[i][columnIndex]
	}
	return column
}

func computeLinearCombination(api frontend.API, in []frontend.Variable, coeffs []*big.Int, offset ...int) frontend.Variable {
	lc := frontend.Variable(0)
	off := 0
	if len(offset) > 0 {
		off = offset[0]
	}
	for i := 0; i < len(in); i++ {
		lc = api.Add(lc, api.Mul(coeffs[off+i], in[i]))
	}
	return lc
}

func MixLast(api frontend.API, in []frontend.Variable, m [][]*big.Int, s int) frontend.Variable {
	column := getColumn(m, s)
	return computeLinearCombination(api, in, column)
}

func MixS(api frontend.API, in []frontend.Variable, s []*big.Int, r int) []frontend.Variable {
	out := make([]frontend.Variable, len(in))
	out[0] = computeLinearCombination(api, in, s, (len(in)*2-1)*r)
	scaleFactor := api.Mul(in[0], s[(len(in)*2-1)*r+len(in)-1])
	for i := 1; i < len(in); i++ {
		out[i] = api.Add(in[i], scaleFactor)
	}
	return out
}
