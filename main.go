package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"os"
	"io"
	"errors"
)

const BLOCKSIZE_BYTE = 16
const BLOCKSIZE_BIT = 16 * 8

func main() {
	app := cli.NewApp()
	app.Name = "Pscrypt"
	app.Description = "Encrypt video files in AES CTR provided a key and optionally and IV"
	app.Version = "0.2.0"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "in, i",
			Usage: "Input file",
		},
		cli.StringFlag{
			Name:  "out, o",
			Usage: "Output file",
		},
		cli.StringFlag{
			Name:  "key, k",
			Usage: fmt.Sprintf("Key as %d-byte hex string (%d characters)", BLOCKSIZE_BYTE, hex.EncodedLen(BLOCKSIZE_BYTE)),
		},
	}

	app.Commands = []cli.Command{
		{
			Name:        "ctr",
			Description: "Operate in counter Mode",
			Action:      ctr,
			Flags: append([]cli.Flag{
				cli.BoolFlag{
					Name:  "implicit-encrypt, E",
					Usage: fmt.Sprintf("Generate a random %d-byte IV and prepend it to the output file", BLOCKSIZE_BYTE),
				},
				cli.BoolFlag{
					Name:  "implicit-decrypt, D",
					Usage: fmt.Sprintf("Use first %d bytes of file as IV for decryption", BLOCKSIZE_BYTE),
				},
				cli.StringFlag{
					Name:  "iv",
					Usage: fmt.Sprintf("IV as %d-byte hex string (%d characters)", BLOCKSIZE_BYTE, hex.EncodedLen(BLOCKSIZE_BYTE)),
					Value: "",
				},
			}, app.Flags...),
		},
		//{
		//	Name:        "gcm",
		//	Description: "Operate in Galois/Counter Mode",
		//	Subcommands: []cli.Command{
				{
					Name:        "encrypt",
					Aliases: []string{"e"},
					Description: "Encrypt input to output",
					Action:      gcm,
					Flags:       app.Flags,
				}, {
					Name:        "decrypt",
					Aliases: []string{"d"},
					Description: "Decrypt input to output",
					Action:      gcm,
					Flags:       app.Flags,
				},
			//},
		//},
	}

	app.ExitErrHandler = func(context *cli.Context, err error) {
		fmt.Fprintln(os.Stderr, err)
	}

	app.Run(os.Args)
}

var source, key []byte
var out io.WriteCloser
var aesCipher cipher.Block

func prepare(ctx *cli.Context) error {
	if ctx.String("in") == "" ||
		ctx.String("out") == "" ||
		ctx.String("key") == "" {

		return errors.New("missing required parameters, see `help`")
	}

	in, err := os.Open(ctx.String("in"))
	if err != nil {
		return err
	}

	ir := bufio.NewReader(in)

	out, err = os.Create(ctx.String("out"))
	if err != nil {
		return err
	}

	key = make([]byte, BLOCKSIZE_BYTE)
	n, err := hex.Decode(key, []byte(ctx.String("key")))
	if err != nil {
		return err
	}
	if n != BLOCKSIZE_BYTE {
		return errors.New(fmt.Sprintf("Provided key is not %d b long", BLOCKSIZE_BIT))
	}

	source, err = ioutil.ReadAll(ir)
	in.Close()

	aesCipher, err = aes.NewCipher(key)
	if err != nil {
		return err
	}

	return nil
}

func ctr(ctx *cli.Context) error {
	err := prepare(ctx)
	if err != nil {
		return err
	}

	iv := make([]byte, BLOCKSIZE_BYTE)

	if ctx.String("iv") != "" {
		n, err := hex.Decode(iv, []byte(ctx.String("iv")))
		if err != nil {
			return err
		}
		if n != BLOCKSIZE_BYTE {
			log.Fatalf("Provided IV is not %d b long", BLOCKSIZE_BIT)
		}
	} else {
		if ctx.Bool("implicit-decrypt") {
			copy(iv, source[:BLOCKSIZE_BYTE])
			source = source[BLOCKSIZE_BYTE:]
		} else if ctx.Bool("implicit-encrypt") {
			n, err := rand.Read(iv)
			if err != nil {
				return err
			}
			if n != BLOCKSIZE_BYTE {
				log.Fatalf("Error gathering %d random bytes for IV", BLOCKSIZE_BIT)
			}
			out.Write(iv)
		} else {
			log.Fatal("You need to provide an IV or use -I/-E option.")
		}
	}

	var destination []byte

	destination = make([]byte, len(source))
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(aesCipher, iv)
	ctr.XORKeyStream(destination, source)

	out.Write(destination)
	out.Close()

	return nil
}

func gcm(ctx *cli.Context) error {
	err := prepare(ctx)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return err
	}

	destination := make([]byte, 0, len(source)+gcm.Overhead())
	if err != nil {
		return err
	}

	if ctx.Command.Name == "decrypt" {
		destination, err = gcm.Open(destination, source[:gcm.NonceSize()], source[gcm.NonceSize():], nil)
		if err != nil {
			return err
		}
	} else if ctx.Command.Name == "encrypt" {
		nonce := make([]byte, gcm.NonceSize())
		n, err := rand.Read(nonce)
		if err != nil {
			return err
		}
		if n != gcm.NonceSize() {
			return errors.New(fmt.Sprintf("Error gathering %d random bytes for IV", BLOCKSIZE_BIT))
		}
		out.Write(nonce)
		destination = gcm.Seal(destination, nonce, source, nil)
	}

	out.Write(destination)

	return nil
}
