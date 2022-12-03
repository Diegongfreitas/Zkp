package main

// Here are the libraries we depend on
import (
	//general imports
	"log"
	"fmt"
	"os"
	"bytes"
	"io/ioutil"
	//"encoding/json"

	//specific imports to include Fabric SDK routines
	"github.com/hyperledger/fabric-sdk-go/pkg/client/channel"
	"github.com/hyperledger/fabric-sdk-go/pkg/client/ledger"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/fabsdk"
	
	//specific imports to include GNARK functions
	"github.com/consensys/gnark/frontend"
	//"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/std/hash/mimc"

	"github.com/consensys/gnark-crypto/ecc"
	
)

type FabClient struct {
	//strings to keep values from channel and user names
	channelname string
	username    string
	//reference to the objects to access ledger and channel invoking
	ledger  *ledger.Client
	channel *channel.Client
}

type Circuit struct {
    File_Num frontend.Variable
    Hash     frontend.Variable `gnark:",public"`
}


// Set the logging level in SDK. The usual level is logging.INFO.
// Check the package ..fabric-sdk-go/pkg/common/logging for more
// options.
func (c *FabClient) SetLogging(lvl logging.Level) {
	//set all the logs with the same level informed by parameter
	logging.SetLevel("fabsdk", lvl)
	logging.SetLevel("fabsdk/common", lvl)
	logging.SetLevel("fabsdk/fab", lvl)
	logging.SetLevel("fabsdk/client", lvl)
}

// Manages the connection with the blockchain network, and instantiate
// two internal properties: *channel, that gives access to the chaincodes;
// and *ledger, that provides basic information about the ledger and channel.
// The input args are the connection profile (complete path to the .yaml
// file), the channel name (or ID) and the user name (usually "Admin").
func (c *FabClient) Connect(connectionprofile string, channelname string, username string) {
	//reads de connection profile (should be an yaml format)
	fmt.Println("Reading connection profile...")
	tempconfig := config.FromFile(connectionprofile)

	//try to instantiate a sdk object
	sdk, err := fabsdk.New(tempconfig)
	if err != nil {
		//in case off error, log and exit
		fmt.Printf("Failed to create new SDK: %s\n", err)
		os.Exit(1)
	}

	//get access to a specific channel context
	context := sdk.ChannelContext(channelname, fabsdk.WithUser(username))

	//set logging level
	c.SetLogging(logging.INFO)

	//get an object ledger to access management info
	c.ledger, err = ledger.New(context)
	if err != nil {
		fmt.Printf("Failed to create channel [%s] client: %#v", channelname, err)
		os.Exit(1)
	}

	//get an object channel to invoke chaincodes
	c.channel, err = channel.New(context)
	if err != nil {
		fmt.Printf("Failed to create channel client: %#v", err)
	}

	//keeps a local record of channel and user names
	c.channelname = channelname
	c.username = username
}

// Invokes a chaincode, and delivers the return in a string format. This
// method depends on a connected FabClient instance. the args are: the
// chaincode name, the internal chaincode function name, and an array of bytes
// containing alll the necessary function parameters.
func (c *FabClient) Invoke(ccname string, funcname string, funcargs [][]byte) string {

	//register log
	fmt.Println("Invoking chaincode", funcname)

	//tests if the client is connected
	if c.channel == nil {
		fmt.Println("Unexpected nil values, client does not connected.")
		os.Exit(1)
	}

	//invoke chaincode, and since any data is needed, discards the return
	response, err := c.channel.Execute(channel.Request{
		ChaincodeID: ccname,
		Fcn:         funcname,
		Args:        funcargs,
	})

	//tests error result
	if err != nil {
		//chaincode failed, generates log
		fmt.Printf("Failed to invoke: %+v\n", err)
	}

	//converts the payload into a string
	ret := string(response.Payload)

	//logs the invoke status
	fmt.Println("Chaincode status: ", response.ChaincodeStatus)

	//deliver return information
	return ret
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

func prover() ([]uint8, bytes.Buffer, error){

	fmt.Println("\n PROVING \n")
	//Retrieving the serealized ProvingKey from the pk.txt file created by the Third Trusted Party
	pkAsBytes, err := ioutil.ReadFile("../keys/pk.txt")				
	
	//Writing pkbytes into a buffer in order to append it's values in a new groth16.ProvingKey type variable
	var pkbuffer bytes.Buffer 	
	pkbuffer.Write(pkAsBytes)									
	
	//Creating new groth16.ProvingKey type variable
	pk := groth16.NewProvingKey(ecc.BN254)						
	
	//Appending pk values from pk.txt file into new groth16.ProvingKey type variable for proof calculation
	_, err = pk.ReadFrom(&pkbuffer)								
	pkbuffer.Reset()

	//Retrieving r1cs from the r1cs.txt file created by the Third Trusted Party
	r1csAsBytes, err := ioutil.ReadFile("../r1cs/r1cs.txt")
	
	var r1csbuffer bytes.Buffer
	r1csbuffer.Write(r1csAsBytes) 

	r1cs := groth16.NewCS(ecc.BN254) 							
	_, err = r1cs.ReadFrom(&r1csbuffer)
	r1csbuffer.Reset()

	//Asking Prover for Witness assignment
	fmt.Println("Please Prover, insert <file hash>: ")			
	var filehash string
	fmt.Scanln(&filehash)
	
	//Creating a constraint satisfiable assignment
	assignment := &Circuit{	
		File_Num: "21765111349035677562249794983296132341094",											
		Hash: 		filehash,																																																															
	}      
	
	//Codifing the assignment in the form of a Witness using Eliptic Curves(BN254)
	witness, err := frontend.NewWitness(assignment, ecc.BN254)	
	
	//Generating Proof and Public Witness
	//Spliting Witness Public Part
	hash, err := witness.Public()										
	
	//Serializing Witness Public Part in order to send it to the verifier
	hashBytes, err := hash.MarshalBinary()						
	
	proof, err := groth16.Prove(r1cs, pk, witness)
	var proofbuffer bytes.Buffer												
	_, err = proof.WriteTo(&proofbuffer) //WriteTo is a groth16 function for writing its types into a bytes buffer 
	
	return hashBytes, proofbuffer, err
}


func main() {
	//First of all, create an instance of FabClient (the internal atributes are initialized with "" and nil)
	fabcli := &FabClient{"", "", nil, nil}

	//Connect to the blockchain, seting up the specific channel and user
	fabcli.Connect("./connection-profile.yaml", "nmi-channel", "Admin")

	packageid, hashBytes, proofbuffer, err := prover()
	if err != nil{
		log.Fatal("Error: ", err)
	}
	
	
	fmt.Println("What do you want to send, hash or proof?: ")			
	var action string
	
	for action != "hash" || action != "proof" {
		fmt.Scanln(&action)
		if action == "hash"{
			
			fmt.Println("Please, choose a packageID: ")			
			var packageid string
			fmt.Scanln(&packageid)

			//Invoking chaincode to register datapackage hash
			response := fabcli.Invoke("fileproof", "registerhash", [][]byte{[]byte(packageid), hashBytes})
			fmt.Println("My chaincode returned this content:", response)

		} else if action == "proof" {
			
			fmt.Println("Please, choose a packageID: ")
			var packageid string
			fmt.Scanln(&packageid)

			proofid := packageid + "-p"
			
			//Invoking chaincode to register proof of knowledge
			response := fabcli.Invoke("fileproof", "registerproof", [][]byte{[]byte(packageid),[]byte(proofid), proofbuffer.Bytes()})
			fmt.Println("My chaincode returned this content:", response)

		} else {
			
			//Invalid Option
			fmt.Println("Please, choose one between these options:\n hash or proof")

		}
	}
}