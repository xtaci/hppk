/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/xtaci/hppk"
)

// keygenCmd represents the keygen command
var keygenCmd = &cobra.Command{
	Use:   "keygen [directory]",
	Short: "generate a hppk private/public key pair",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.ExactArgs(1)(cmd, args); err != nil {
			return errors.New("Missing directory, Use `hppktool keygen -h` to see how the usage.\n")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		dir := args[0]
		order, err := cmd.Flags().GetInt("order")
		if err != nil {
			panic("cannot get param -> order")
		}

		priv, err := hppk.GenerateKey(order)
		if err != nil {
			panic(err)
		}

		// let user confirm
		prefix := "id_hppk"
		privFile := fmt.Sprintf("%v/%v", dir, prefix)
		pubFile := fmt.Sprintf("%v/%v.pub", dir, prefix)

		fmt.Print("Do you want to save the key pair to the following files?\n\n")
		fmt.Printf("Polynomial order:%d\n", order)
		fmt.Printf("[1/2] Private key: %v\n", privFile)
		fmt.Printf("[2/2] Public key: %v\n", pubFile)
		fmt.Print("Proceed with key generation? [y/N]: ")
		reader := bufio.NewReader(os.Stdin)
		char, _, err := reader.ReadRune()

		switch char {
		case 'Y', 'y':
		default:
			return
		}

		// write private key
		bts, err := json.Marshal(priv)
		if err != nil {
			panic(err)
		}

		fPriv, err := os.OpenFile(privFile, os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		defer fPriv.Close()
		_, err = fPriv.Write(bts)
		if err != nil {
			panic(err)
		}

		// write public key
		fPub, err := os.OpenFile(pubFile, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
		defer fPub.Close()

		bts, err = json.Marshal(&priv.PublicKey)
		if err != nil {
			panic(err)
		}

		_, err = fPub.Write(bts)
		if err != nil {
			panic(err)
		}

		fmt.Println("Done.")
	},
}

func init() {
	rootCmd.AddCommand(keygenCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// keygenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	keygenCmd.Flags().IntP("order", "o", 5, "the order of the polynomial")
}
