package main

import (
	
	bn254 	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"fmt"
	"math/big"
	"log"
	"os"
)

func mimcHash(data []byte) string {
	f := bn254.NewMiMC()
	f.Write(data)
	hash := f.Sum(nil)
	hashInt := big.NewInt(0).SetBytes(hash)
	return hashInt.String()
}

func preimageHash(){

	fmt.Println("Insert preimage: ")
	var preimage string
	fmt.Scanln(&preimage)

	var bignum, _ = new(big.Int).SetString(preimage, 0)
	//fmt.Println(bignum)

	preImage := bignum.Bytes()
	fmt.Printf("preImage: %s\n", preImage)
	//Ex: 16130099170765464552823636852555369511329944820189892919423002775646948828469
	
	hash := mimcHash(preImage)
	fmt.Printf("hash: %s\n", hash)
	//Ex: 8674594860895598770446879254410848023850744751986836044725552747672873438975
}


func fileHash(){

	fmt.Println("Insert file full path:") 
	//Ex: /home/diego/Pictures/Jack.jpg
	var path string
	fmt.Scanln(&path)

	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var data string
	for i:= 0; i<32; i++{
		data =  data + fmt.Sprintf("%b", file[i])
		//data = fmt.Sprintf("%b", file[i])
		//fmt.Println(data)
	}
	var bignum, _ = new(big.Int).SetString(data, 2)
	fmt.Println("bignum: ", bignum)
	//Ex: 21765111349035677562249794983296132341094
	
	preImage := bignum.Bytes()
	fmt.Printf("preImage: %s\n", preImage)

	hash := mimcHash(preImage)
	fmt.Printf("hash: %s\n", hash)
	//Ex: 12142150701098388651302243805247910737235100285969480065059285355433989764788

}

func main(){
	//preimageHash()
	fileHash()
}