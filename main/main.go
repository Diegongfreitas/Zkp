package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	//"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark-crypto/ecc"
	"fmt"
	"bytes"
	"io/ioutil"
	"os"
	//"encoding/json"	
)

// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
    File_Num frontend.Variable
    Hash     frontend.Variable `gnark:",public"`
}


var publicWitnessBytes []byte
var publicWitness *witness.Witness

// Define declares the circuit's constraints
func (circuit *Circuit) Define(api frontend.API) error {
    // hash function
    mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.File_Num)
    // specify constraints
    // mimc(preImage) == hash
    api.AssertIsEqual(circuit.Hash, mimc.Sum())

    return nil
}

func ttp(){
	//------------------------------------------------------Generating R1CS---------------------------------------------------------
	var mimcCircuit Circuit
	r1cs, _ := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &mimcCircuit)	
	var r1csbuffer bytes.Buffer
	_, _ = r1cs.WriteTo(&r1csbuffer)
	//fmt.Println("r1csbuffer: ", r1csbuffer)	

	//-------------------------------------------------------Sending R1CS----------------------------------------------------------
	
	os.Mkdir("prover", 0777)												//Creating directory to store Prover files
	_ = ioutil.WriteFile("prover/r1cs.txt", r1csbuffer.Bytes(), 0666)		//Storing the R1CS into r1cs.txt file
	r1csbuffer.Reset()

	//----------------------------------------------------- Generating pk&vk---------------------------------------------------------
	
	pk, vk, _ := groth16.Setup(r1cs)										//TTP creating proving key and verifying key with groth16 zkSNARK: Setup
	
	var pkbuffer bytes.Buffer												//Serializing the ProvingKey in order to store it in a file
	_, _ = pk.WriteTo(&pkbuffer)
	//fmt.Println("pkbuffer: ", pkbuffer)	
	
	var vkbuffer bytes.Buffer												//Serializing the VerifyingKey in order to store it in a file
	_, _ = vk.WriteTo(&vkbuffer)
	//fmt.Println("vkbuffer: ", vkbuffer)
	
	//-------------------------------------------------------Sending pk-----------------------------------------------------------

	os.Mkdir("keys", 0777)													//Creating directory to store the proving and verifying keys
	_ = ioutil.WriteFile("keys/pk.txt", pkbuffer.Bytes(), 0666)				//Storing the ProvingKey into pk.txt file
	pkbuffer.Reset()

	_ = ioutil.WriteFile("keys/vk.txt", vkbuffer.Bytes(), 0666)				//Storing the VerifyingKey into vk.txt file
	vkbuffer.Reset()
}


func prover(){
	
	//-------------------------------------------------------Retrieving pk-----------------------------------------------------------

	pkAsBytes, _ := ioutil.ReadFile("keys/pk.txt")				//Retrieving the serealized ProvingKey from the pk.txt file created by the Third Trusted Party
	//fmt.Println("pkAsBytes: ", pkAsBytes)
	var pkbuffer bytes.Buffer 	
	pkbuffer.Write(pkAsBytes)									//Writing pkbytes into a buffer in order to append it's values in a new groth16.ProvingKey type variable
	//fmt.Println("pkbuffer: ", pkbuffer)		
	pk := groth16.NewProvingKey(ecc.BN254)						//Creating new groth16.ProvingKey type variable
	_, _ = pk.ReadFrom(&pkbuffer)								//Appending pk values from pk.txt file into new groth16.ProvingKey type variable for proof calculation
	pkbuffer.Reset()
	
	//-------------------------------------------------------Retrieving R1CS----------------------------------------------------------

	r1csAsBytes, _ := ioutil.ReadFile("prover/r1cs.txt")		
	//fmt.Println("r1csAsBytes: ", r1csAsBytes)
	var r1csbuffer bytes.Buffer
	r1csbuffer.Write(r1csAsBytes)
	//fmt.Println("r1csbuffer: ", r1csbuffer) 
	r1cs := groth16.NewCS(ecc.BN254) 							
	_, _ = r1cs.ReadFrom(&r1csbuffer)
	r1csbuffer.Reset()

	//-----------------------------------------------Asking Prover for Witness assignment---------------------------------------------

	fmt.Println("Please Prover, insert hash: ")			
	var file_hash string
	fmt.Scanln(&file_hash)

	assignment := &Circuit{																			//Creating a constraint satisfiable assignment
		Hash: 		file_hash,																		//both with 77 characters
		File_Num: "21765111349035677562249794983296132341094",	//witness limit is 32 bytes																							
	}      

	witness, _ := frontend.NewWitness(assignment, ecc.BN254)	//Codifing the assignment in the form of a Witness using Eliptic Curves(BN254)

	//----------------------------------------------Generating Proof and Public Witness----------------------------------------------------
	publicWitness, _ = witness.Public()						//Spliting Witness Public Part
	fmt.Printf("publicWitness: \n", publicWitness)
	//publicWitnessBytesVector := publicWitness.Vector.MarshalJSON()			//Serializing Witness Public Part in order to send it to the verifier
	//fmt.Println("publicbytes: \n", publicWitnessBytesVector)
	publicWitnessBytes, _ = publicWitness.MarshalJSON()
	fmt.Println("publicWitnessBytes: \n", publicWitnessBytes)
				
	proof, _ := groth16.Prove(r1cs, pk, witness)				
	fmt.Println("proof: \n", proof)
	var proofbuffer bytes.Buffer
	_, _ = proof.WriteTo(&proofbuffer)							


	//-------------------------------------------------Sending Proof and Public Witness---------------------------------------------------

	_ = ioutil.WriteFile("prover/proof.txt", proofbuffer.Bytes(), 0666)	//Storing proof into a file that is going to be read by the verifier
	proofbuffer.Reset()
	//_ = ioutil.WriteFile("prover/public_witness.txt", publicWitnessBytes, 0666)	//Storing proof into a file that is going to be read by the verifier
	//_ = ioutil.WriteFile("prover/public_witness_vector.txt", publicWitnessBytesVector, 0666)
	
}



func verifier(){	

	//--------------------------------------------------------Retrieving vk-----------------------------------------------------------------
	fmt.Println("\n VERIFYING \n")
	vkAsBytes, _ := ioutil.ReadFile("keys/vk.txt")			//Retrieving the serealized VerifyingKey from the vk.txt file created by the Third Trusted Party
	//fmt.Println("vkAsBytes: ", vkAsBytes)
	var vkbuffer bytes.Buffer
	vkbuffer.Write(vkAsBytes)								//Writing pkbytes into a buffer in order to append it's values in a new groth16.VerifyingKey type variable
	//fmt.Println("vkbuffer: ", vkbuffer)		
	vk := groth16.NewVerifyingKey(ecc.BN254)				//Creating new groth16.VerifyingKey type variable
	_, _ = vk.ReadFrom(&vkbuffer)							//Appending vk values from vk.txt file into new groth16.VerifyingKey type variable for verification
	vkbuffer.Reset()
	//fmt.Println("vk: ", vk)		

	//--------------------------------------------------------Retrieving Proof--------------------------------------------------------------
	proofAsBytes, _ := ioutil.ReadFile("prover/proof.txt")
	var proofbuffer bytes.Buffer
	proofbuffer.Write(proofAsBytes)
	proof := groth16.NewProof(ecc.BN254)					//Creating new groth16.Proof type variable		
	_, _ = proof.ReadFrom(&proofbuffer)						//Retrieving Proof
	proofbuffer.Reset()
	//fmt.Println("proof:", proof)
	
	//------------------------------------------------------Retrieving Public Witness-------------------------------------------------------
	
	//publicWitnessBytes, _ := ioutil.ReadFile("prover/public_witness.txt")
	//publicWitnessBytesVector, _ := ioutil.ReadFile("prover/public_witness_vector.txt")
		
	fmt.Println("publicWitnessbytes:", publicWitnessBytes)
	//fmt.Println("publicWitnessBytesVector: ", publicWitnessBytesVector)
	//v, err := *witness.newVector(ecc.BN254)
	publicWitness.UnmarshalJSON(publicWitnessBytes)
	fmt.Println("publicWitness:", publicWitness)
	//json.Unmarshal(publicWitnessBytesVector, &v)
	
	/* 
	publicWitness = &witness.Witness{
		CurveID: ecc.BN254,
		Vector:  v,
	}
	*/
	
	//publicWitness.Vector = 	*witness.Vector(publicWitnessVector)

	
	//fmt.Println("publicvector:", v)
	
	
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