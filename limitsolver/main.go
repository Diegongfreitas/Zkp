package main

import (
	
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"	
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/backend/witness"
	
	"github.com/consensys/gnark-crypto/ecc"
	bn254 	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"math/big"
	"log"
	"fmt"
	"bytes"
	"io/ioutil"
	"os"	

)


type Circuit struct {
	// Circuit defines a file knowledge proof
	// mimc(secret File) = public hash
    Hash     frontend.Variable `gnark:",public"`
	File_Bytes []frontend.Variable
    }


func (circuit *Circuit) Define(api frontend.API) error {
	// Define declares the circuit's constraints
    mimc, _ := mimc.NewMiMC(api)	
	mimc.Write(circuit.File_Bytes[:])
    // specify constraints
    // mimc(File_Bytes) == Hash
    api.AssertIsEqual(circuit.Hash, mimc.Sum())

    return nil
}

func fileHash() ([]byte, []frontend.Variable){
	fmt.Println("Insert file full path:") 
	//Ex: /home/diego/Pictures/Jack.jpg
	var path string
	fmt.Scanln(&path)

	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	limit := (len(file)/32)+(len(file)%32)
	var file_bytes []frontend.Variable
	var bignum []*big.Int
	goMimc := bn254.NewMiMC()
	for j:=0; j < limit; j++{
		// minimal cs res = hash(data)
		var data []string
		for i:= 0; i < 32; i++{
			data[j] = data[j] + fmt.Sprintf("%b", file[i])
		}

		// running MiMC (Go)
		
		bignum[j], _ = new(big.Int).SetString(data[j], 2)
		goMimc.Write(bignum[j].Bytes())

		// assert correctness against correct witness
		file_bytes[j] = data[j]
	}
	file_hash := goMimc.Sum(nil)
	return file_hash, file_bytes
}

func ttp(){
	//------------------------------------------------------Generating R1CS---------------------------------------------------------
	
	var mimcCircuit Circuit
	r1cs, _ := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &mimcCircuit)	
	var r1csbuffer bytes.Buffer
	_, _ = r1cs.WriteTo(&r1csbuffer)	


	//-------------------------------------------------------Sending R1CS----------------------------------------------------------
	
	os.Mkdir("prover", 0777)												//Creating directory to store Prover files
	_ = ioutil.WriteFile("prover/r1cs.txt", r1csbuffer.Bytes(), 0666)		//Storing the R1CS into r1cs.txt file
	r1csbuffer.Reset()

	//----------------------------------------------------- Generating pk&vk---------------------------------------------------------
	
	pk, vk, _ := groth16.Setup(r1cs)										//TTP creating proving key and verifying key with groth16 zkSNARK: Setup
	
	var pkbuffer bytes.Buffer												//Serializing the ProvingKey in order to store it in a file
	_, _ = pk.WriteTo(&pkbuffer)
		
	
	var vkbuffer bytes.Buffer												//Serializing the VerifyingKey in order to store it in a file
	_, _ = vk.WriteTo(&vkbuffer)
	
	
	//-------------------------------------------------------Sending pk-----------------------------------------------------------

	os.Mkdir("keys", 0777)													//Creating directory to store the proving and verifying keys
	_ = ioutil.WriteFile("keys/pk.txt", pkbuffer.Bytes(), 0666)				//Storing the ProvingKey into pk.txt file
	pkbuffer.Reset()

	_ = ioutil.WriteFile("keys/vk.txt", vkbuffer.Bytes(), 0666)				//Storing the VerifyingKey into vk.txt file
	vkbuffer.Reset()
}


func prover(){
	
	//-------------------------------------------------------Retrieving pk-----------------------------------------------------------
	fmt.Println("\n PROVING \n")
	pkAsBytes, _ := ioutil.ReadFile("keys/pk.txt")				//Retrieving the serealized ProvingKey from the pk.txt file created by the Third Trusted Party
	
	var pkbuffer bytes.Buffer 	
	pkbuffer.Write(pkAsBytes)									//Writing pkbytes into a buffer in order to append it's values in a new groth16.ProvingKey type variable
			
	pk := groth16.NewProvingKey(ecc.BN254)						//Creating new groth16.ProvingKey type variable
	_, _ = pk.ReadFrom(&pkbuffer)								//Appending pk values from pk.txt file into new groth16.ProvingKey type variable for proof calculation
	pkbuffer.Reset()
	
	//-------------------------------------------------------Retrieving R1CS----------------------------------------------------------
	
	r1csAsBytes, _ := ioutil.ReadFile("prover/r1cs.txt")

	var r1csbuffer bytes.Buffer
	r1csbuffer.Write(r1csAsBytes) 

	r1cs := groth16.NewCS(ecc.BN254) 							
	_, _ = r1cs.ReadFrom(&r1csbuffer)
	r1csbuffer.Reset()

	//-----------------------------------------------Asking Prover for Witness assignment---------------------------------------------
	
	file_hash, file_bytes := fileHash()
	

	assignment := &Circuit{	//Creating a constraint satisfiable assignment											
		Hash: 		file_hash,
		File_Bytes: 	file_bytes,																																																															
	}      

	witness, _ := frontend.NewWitness(assignment, ecc.BN254)	//Codifing the assignment in the form of a Witness using Eliptic Curves(BN254)
	
	//----------------------------------------------Generating Proof and Public Witness----------------------------------------------------

	publicWitness, _ := witness.Public()										//Spliting Witness Public Part
	fmt.Printf("publicWitness: %s \n", publicWitness)
	publicWitnessBytes, _ := publicWitness.MarshalBinary()						//Serializing Witness Public Part in order to send it to the verifier
	//publicWitnessBytes type: []uint8
	proof, _ := groth16.Prove(r1cs, pk, witness)				
	//proof type: *groth16.Proof 
	var proofbuffer bytes.Buffer												
	_, _ = proof.WriteTo(&proofbuffer)											//Serializing Proof in order to send it to the verifier


	//-------------------------------------------------Sending Proof and Public Witness---------------------------------------------------

	_ = ioutil.WriteFile("prover/proof.txt", proofbuffer.Bytes(), 0666)			//Storing proof into a file that is going to be read by the verifier
	proofbuffer.Reset()
	_ = ioutil.WriteFile("prover/public_witness.txt", publicWitnessBytes, 0666)	//Storing publicwitness into a file that is going to be read by the verifier
	
	
}



func verifier(){	
	fmt.Println("\n VERIFYING \n")
	//--------------------------------------------------------Retrieving vk-----------------------------------------------------------------

	vkAsBytes, _ := ioutil.ReadFile("keys/vk.txt")			//Retrieving the serealized VerifyingKey from the vk.txt file created by the Third Trusted Party
	
	var vkbuffer bytes.Buffer
	vkbuffer.Write(vkAsBytes)								//Writing pkbytes into a buffer in order to append it's values in a new groth16.VerifyingKey type variable		
	
	vk := groth16.NewVerifyingKey(ecc.BN254)				//Creating new groth16.VerifyingKey type variable
	_, _ = vk.ReadFrom(&vkbuffer)							//Appending vk values from vk.txt file into new groth16.VerifyingKey type variable for verification
	vkbuffer.Reset()


	//--------------------------------------------------------Retrieving Proof--------------------------------------------------------------
	proofAsBytes, _ := ioutil.ReadFile("prover/proof.txt")
	
	var proofbuffer bytes.Buffer
	proofbuffer.Write(proofAsBytes)
	
	proof := groth16.NewProof(ecc.BN254)					//Creating new groth16.Proof type variable		
	fmt.Printf("type: %T", proof)
	_, _ = proof.ReadFrom(&proofbuffer)						//Retrieving Proof
	proofbuffer.Reset()

	
	//------------------------------------------------------Retrieving Public Witness-------------------------------------------------------
	
	publicWitnessBytes, _ := ioutil.ReadFile("prover/public_witness.txt")	

	publicWitness := &witness.Witness{CurveID: ecc.BN254,} 
	
	publicWitness.UnmarshalBinary(publicWitnessBytes)
	fmt.Println("publicWitness: ", publicWitness)
	//-------------------------------------------------------------Verifying Proof----------------------------------------------------------
	err := groth16.Verify(proof, vk, publicWitness)				
	if err != nil{
		fmt.Println(err)
	} else{
		fmt.Println("Proof Verified")
	}
}

func main(){
	ttp()	  		//After generating a key pair once with ttp(), we can stop instantiating it, with the stored pair different proofs are generated and validated
	prover()
	verifier()
}