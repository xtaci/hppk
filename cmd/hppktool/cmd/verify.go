/*
Copyright © 2024 xtaci <imap@live.com>
*/
package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"github.com/xtaci/hppk"
)

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "verify a message from standard input",
	Long: `Verify a HPPK signed message from standard input against the signature file and public key.
The message is first SHA256 hashed, unless -raw is specified`,
	Run: func(cmd *cobra.Command, args []string) {
		silent, err := cmd.Flags().GetBool("silent")
		if err != nil {
			panic("cann't get param -> silent")
		}

		paramPub, err := cmd.Flags().GetString("pubkey")
		if err != nil {
			panic("cannot get param -> pubkey")
		}

		paramSigFile, err := cmd.Flags().GetString("sigfile")
		if err != nil {
			panic("cannot get param -> signature")
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

		// open the signature
		fSignature, err := os.Open(paramSigFile)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer fSignature.Close()

		// read the public key
		pub := &hppk.PublicKey{}
		err = json.NewDecoder(fPub).Decode(pub)
		if err != nil {
			fmt.Println(err)
			return
		}

		// read the signature
		sig := &hppk.Signature{}
		err = json.NewDecoder(fSignature).Decode(sig)
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

		// verify the signature
		if hppk.VerifySignature(sig, message, pub) {
			fmt.Println("\nSignature Verified.")
		} else {
			fmt.Println("\nSignature NOT verfied.")
		}
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	verifyCmd.Flags().StringP("pubkey", "p", "./id_hppk.pub", "the HPPK public key file to verify against.")
	verifyCmd.Flags().String("sigfile", "./sigfile", "the signed signature file.")
	verifyCmd.Flags().Bool("raw", false, "encrypt the raw message, the message length must not exceed 256 bytes.")
}
