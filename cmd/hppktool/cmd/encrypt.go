/*
Copyright © 2024 xtaci <imap@live.com>
*/
package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/xtaci/hppk"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "encrypts a message from standard input",
	Long:  `the message will first be SHA256 hashed and then encrypted using HPPK, unless -raw is specified`,
	Run: func(cmd *cobra.Command, args []string) {
		silent, err := cmd.Flags().GetBool("silent")
		if err != nil {
			panic("cann't get param -> silent")
		}

		paramPub, err := cmd.Flags().GetString("pubkey")
		if err != nil {
			panic("cannot get param -> pubkey")
		}

		paramRaw, err := cmd.Flags().GetBool("raw")
		if err != nil {
			panic("cannot get param -> raw")
		}

		// open the public key file
		fPub, err := os.Open(paramPub)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer fPub.Close()

		// sign the hash with the public key
		pub := &hppk.PublicKey{}
		err = json.NewDecoder(fPub).Decode(pub)
		if err != nil {
			fmt.Println(err)
			return
		}

		// read the message from stdin
		var message []byte
		if paramRaw {
			message = make([]byte, 256)
			count := 0
			lr := io.LimitReader(os.Stdin, 256)
			for {
				n, err := lr.Read(message[count:])
				count += n
				if err == io.EOF {
					break
				}

				if err != nil {
					fmt.Println(err)
					return
				}
			}
			message = message[:count]
			if !silent {
				fmt.Printf("RAW(hex):%v\n", hex.EncodeToString(message))
			}
		} else {
			h := sha256.New()
			if _, err := io.Copy(h, os.Stdin); err != nil {
				fmt.Println(err)
				return
			}
			message = h.Sum(nil)
			if !silent {
				fmt.Printf("SHA256(hex):%v\n", hex.EncodeToString(message))
			}
		}

		// encrypt the message
		kem, err := hppk.Encrypt(pub, message)
		var jsonBuffer bytes.Buffer
		err = json.NewEncoder(&jsonBuffer).Encode(kem)
		if err != nil {
			fmt.Println(err)
			return
		}

		if !silent {
			fmt.Printf("Encrypted:\n")
		}
		fmt.Print(string(jsonBuffer.Bytes()))
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// encryptCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// encryptCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	encryptCmd.Flags().StringP("pubkey", "p", "./id_hppk.pub", "the hppk public key file")
	encryptCmd.Flags().Bool("raw", false, "encrypt the raw message, the message length must not exceed 256 bytes")
}
