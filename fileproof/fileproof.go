package main

import (
	//general imports
	"fmt"
	//"bytes"
	//"io/ioutil"	
	"encoding/json"
	"os"
	"reflect"
	//these imports are for Hyperledger Fabric interface
	"github.com/hyperledger/fabric/core/chaincode/shim"
	sc "github.com/hyperledger/fabric/protos/peer"

	//specific imports to include GNARK functions
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark-crypto/ecc"
	
)

type SmartContract struct {
}

type DataPackage struct{
	Hash []byte
}

type Proof struct {
	ProofID string
	ProofValues []byte
    IsValid bool
	Timestamp string
}

// Init method is called when the auction is instantiated.
// Best practice is to have any Ledger initialization in separate function.
// Note that chaincode upgrade also calls this function to reset
// or to migrate data, so be careful to avoid a scenario where you
// inadvertently clobber your ledger's data!
func (s *SmartContract) Init(stub shim.ChaincodeStubInterface) sc.Response {
	return shim.Success(nil)
}

// Invoke function is called on each transaction invoking the chaincode. It
// follows a structure of switching calls, so each valid feature need to
// have a proper entry-point.
func (s *SmartContract) Invoke(stub shim.ChaincodeStubInterface) sc.Response {
	// extract the function name and args from the transaction proposal
	fn, args := stub.GetFunctionAndParameters()

	//implements a switch for each acceptable function
	if fn == "registerhash" {
		//registers a new hash into the ledger
		return s.registerhash(stub, args)
	} /*else if fn == "registerproof" {
		//verifies the last proof registered into the ledger
			return s.registerproof(stub, args)
		} else if fn == "verify" {
	//verifies the last proof registered into the ledger
		return s.verify(stub, args)
		
	//function fn not implemented, notify error
	} */
	return shim.Error("Chaincode does not support this function.")
}



func (s *SmartContract) registerhash(stub shim.ChaincodeStubInterface, args []string) sc.Response {
	//validate args vector lenght
	if len(args) != 2 {
		return shim.Error("It was expected the parameters to start verification: <packageID> <hashbytes>")
	}
	//gets the parameters associated with each argument
	packageid := args[0]
	hashbytes := args[1]
	
	//loging...
	fmt.Println("Testing args: ", packageid, hashbytes)

	//create asset variable storing datapackage hash in bytes
	var datapackage = DataPackage{Hash:[]byte(hashbytes)}
	
	packageAsBytes, _ := json.Marshal(datapackage)
	
	//registers hash in the ledger
	stub.PutState(packageid, packageAsBytes)

	//loging...
	fmt.Println("Registering Data Package: ", datapackage)
	
	_ = groth16.NewProof(ecc.BN254)
	_ = &witness.Witness{CurveID: ecc.BN254,} 
	return shim.Success(nil)

}	

func dummy(){
	_,_ =os.ReadDir("../keys/")	
	a := 1
	_ = reflect.TypeOf(a)
} 
/*
func (s *SmartContract) registerproof(stub shim.ChaincodeStubInterface, args []string) sc.Response {
	//validate args vector lenght
	if len(args) != 3 {
		return shim.Error("It was expected the parameters to start verification: <packageID> <hashbytes>")
	}
	//gets the parameters associated with each argument
	packageid := args[0]
	proofid := args[1]
	proofvalues := args[2]
	
	hashbytes, err := stub.GetState(packageid)
	if carAsBytes == nil {
		fmt.Println("There ins't a register for the mentioned datapackage and hash")
		return shim.Error("Error on retrieving package register")
	}
	var datapackage = DataPackage{}

	json.Unmarshal(hashbytes, &datapackage) //Retrieving DataPackage Hash 
	
	timestamp, _ := stub.GetTxTimestamp()
	time.Unix(timestamp.Seconds, int64(timestamp.Nanos)).String()
	
	//creates proof record
	proof := Proof{ProofID: proofid, ProofValues: proofvalues, IsValid: false, Timestamp: time}
	//encapsulates proof in a JSON structure
	proofAsBytes, _ = json.Marshal(proof)
	//registers proof in the ledger
	stub.PutState(proofid, proofAsBytes)
	//loging...
	fmt.Println("Registering new proof: ", proof)

	return shim.Success(nil)
}	
*/
/*func (s *SmartContract) verifier(stub shim.ChaincodeStubInterface, args []string) sc.Response {	
	//validate args vector lenght
	if len(args) != 3 {
		return shim.Error("It was expected the parameters to start verification: <vkpath> <proofpath> <hashpath>")
	}//--------------------------------------------------------Retrieving vk-----------------------------------------------------------------
	proofid := 
	proof := args[1]
	vk := args[0]
	hash := args[2]

	vkAsBytes, _ := ioutil.ReadFile("vkpath")			//Retrieving the serealized VerifyingKey from the vk.txt file created by the Third Trusted Party
	
	var vkbuffer bytes.Buffer
	vkbuffer.Write(vkAsBytes)								//Writing pkbytes into a buffer in order to append it's values in a new groth16.VerifyingKey type variable		
	
	vk := groth16.NewVerifyingKey(ecc.BN254)				//Creating new groth16.VerifyingKey type variable
	_, _ = vk.ReadFrom(&vkbuffer)							//Appending vk values from vk.txt file into new groth16.VerifyingKey type variable for verification
	vkbuffer.Reset()


	//--------------------------------------------------------Retrieving Proof--------------------------------------------------------------
	proofAsBytes, _ := ioutil.ReadFile("proofpath")
	
	var proofbuffer bytes.Buffer
	proofbuffer.Write(proofAsBytes)
	
	proof := groth16.NewProof(ecc.BN254)					//Creating new groth16.Proof type variable		
	_, _ = proof.ReadFrom(&proofbuffer)						//Retrieving Proof
	proofbuffer.Reset()

	
	//------------------------------------------------------Retrieving Public Witness-------------------------------------------------------
	
	hashBytes, _ := ioutil.ReadFile(Hashpath)	

	hash := &witness.Witness{CurveID: ecc.BN254,} 
	
	hash.UnmarshalBinary(hashBytes)
	fmt.Println("hash: ", hash)
	//Verifying Proof
	err := groth16.Verify(proof, vk, hash)				
	if err != nil{
		fmt.Println(err)
	} else{
		fmt.Println("Proof Verified")
	}
}
*/

/*
 * The main function starts up the chaincode in the container during instantiate
*/
func main() {

	////////////////////////////////////////////////////////
	// USE THIS BLOCK TO COMPILE THE CHAINCODE
	if err := shim.Start(new(SmartContract)); err != nil {
		fmt.Println("Error starting SmartContract chaincode: %s\n", err)
	}
	////////////////////////////////////////////////////////
}