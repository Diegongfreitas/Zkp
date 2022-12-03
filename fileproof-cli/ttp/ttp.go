package main

// Here are the libraries we depend on
import (
	//general imports
	"os"
	"bytes"
	"io/ioutil"

	//specific imports to include GNARK functions
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark-crypto/ecc"
	
)

type Circuit struct {
    File_Num frontend.Variable
    Hash     frontend.Variable `gnark:",public"`
}


// Define declares the circuit's constraints
func (circuit *Circuit) Define(api frontend.API) error {

    mimc, _ := mimc.NewMiMC(api)	
	mimc.Write(circuit.File_Num)
    // specify constraints
    // mimc(File_Num) == Hash
    api.AssertIsEqual(circuit.Hash, mimc.Sum())

    return nil
}

func ttp(){
	
	var mimcCircuit Circuit
	r1cs, _ := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &mimcCircuit)	
	var r1csbuffer bytes.Buffer
	_, _ = r1cs.WriteTo(&r1csbuffer)	

	//Creating directory to store Prover files
	os.Mkdir("../r1cs", 0777)
	
	//Storing the R1CS into r1cs.txt file												
	_ = ioutil.WriteFile("../r1cs/r1cs.txt", r1csbuffer.Bytes(), 0666)		
	r1csbuffer.Reset()
	
	//TTP creating proving key and verifying key with groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(r1cs)										
	//Serializing the ProvingKey in order to store it in a file
	var pkbuffer bytes.Buffer												
	_, _ = pk.WriteTo(&pkbuffer)
		
	//Serializing the VerifyingKey in order to store it in a file
	var vkbuffer bytes.Buffer												
	_, _ = vk.WriteTo(&vkbuffer)

	//Creating directory to store the proving and verifying keys
	os.Mkdir("../keys", 0777)
	
	//Storing the ProvingKey into pk.txt file													
	_ = ioutil.WriteFile("../keys/pk.txt", pkbuffer.Bytes(), 0666)				
	pkbuffer.Reset()

	_ = ioutil.WriteFile("../keys/vk.txt", vkbuffer.Bytes(), 0666)				
	vkbuffer.Reset()
}

// Example of a main function using the FabClient object.
func main() {
	ttp()
}