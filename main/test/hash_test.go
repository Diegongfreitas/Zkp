package main 
import (
	//"math/big"
	"testing"
	"fmt"
	"log"
	"os"
	//"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark-crypto/ecc"
)

type mimcCircuit struct {
	ExpectedResult frontend.Variable `gnark:"data,public"`
	Data           []frontend.Variable
}

func (circuit *mimcCircuit) Define(api frontend.API) error {
	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mimc.Write(circuit.Data[:]...)
	result := mimc.Sum()
	//fmt.Println(result)
	api.AssertIsEqual(result, circuit.ExpectedResult)
	return nil
}

func TestMimcAll(t *testing.T){
	assert := test.NewAssert(t)
	// minimal cs res = hash(data)
	var circuit, witness mimcCircuit
	
	//fmt.Println("Insert file full path:") 
	//Ex: /home/diego/Pictures/Jack.jpg
	//var path string
	//fmt.Scanln(&path)

	file, err := os.ReadFile("/home/diego/Pictures/Jack.jpg")
	if err != nil {
		log.Fatal(err)
	}

	// running MiMC (Go)
	goMimc := hash.MIMC_BN254.New()
	for i := 0; i < len(file); i+=32{
		if (len(file) - i) >= 32{
			goMimc.Write(file[i:i+31])
		}else{
			goMimc.Write(file[i:len(file)])
		}
	}
	expectedh := goMimc.Sum(nil)
	witness.ExpectedResult = expectedh
	fmt.Println(witness.ExpectedResult)
	
	// assert correctness against correct witness
	witness.Data = make([]frontend.Variable, len(file))
	for i := 0; i < len(file); i++ {
		if (len(file) - i) >= 32{
			witness.Data[i] = file[i:i+31]
		}else{
			witness.Data[i] = file[i:len(file)]
		}
	}
	
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
}
