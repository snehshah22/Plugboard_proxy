package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

type Progress struct {
	bytes int64
}

var ErrShortWrite = errors.New("short write")

var ErrShortBuffer = errors.New("short buffer")

// var salt = "mysalt"

func encrypt(data []byte, mykey string) []byte {
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		log.Printf("Error %s", err)
		// os.Exit(3)
	}
	// key := pbkdf2.Key([]byte(mykey), []byte(salt), 2048, sha256.Size, sha256.New)
	key := pbkdf2.Key([]byte(mykey), salt, 2048, sha256.Size, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error %s", err)
		// os.Exit(3)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error %s", err)
		// os.Exit(3)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Printf("Error %s", err)
		// os.Exit(3)
	}
	salt_nonce := append(salt[:], nonce[:]...)

	ciphertext := gcm.Seal(salt_nonce, nonce, data, nil)
	return ciphertext
}

func decrypt(data []byte, mykey string) []byte {
	salt := data[:8]
	// key := pbkdf2.Key([]byte(mykey), []byte(salt), 2048, sha256.Size, sha256.New)
	key := pbkdf2.Key([]byte(mykey), salt, 2048, sha256.Size, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Printf("Error %s", err)
		// os.Exit(3)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("Error %s", err)
		// os.Exit(3)
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[8:8+nonceSize], data[8+nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Error %s", err)

	}
	return plaintext
}

func Server(proto string, listen string, filecontent string, addr string, prt string) {
	ln, err := net.Listen(proto, ":"+listen)
	if err != nil {
		log.Fatalln(err)
		return
	}
	log.Println("Listening ", proto+":"+listen)

	for {
		con, err := ln.Accept()
		if err != nil {
			log.Fatalln(err)
			break
		} else {
			log.Printf("[%s]: Connection opened\n", con.RemoteAddr())
			rcon, err1 := net.Dial(proto, addr+":"+prt)
			if err1 != nil {
				log.Println(err1)
				con.Close()
				continue
			}
			log.Println("Connected ", addr+":"+prt)
			c := make(chan Progress)
			go TransferStreams(con, c, filecontent, rcon, 1)
		}
	}
}

func TransferStreams(con net.Conn, c chan Progress, filecontent string, rcon net.Conn, flag int) {

	copy := func(r io.ReadCloser, w io.WriteCloser, filecontent string) {
		defer func() {
			r.Close()
			w.Close()
		}()
		var a bool = false
		if flag == 0 {
			if r == os.Stdin {
				a = true
			}
		} else {
			if r == rcon {
				a = true
			}
		}
		if a {
			buf := make([]byte, 64*1024)
			var written int64 = 0
			for {
				nr, er := r.Read(buf)
				if er != nil {
					log.Println("Read Error", er)
					break
				}
				if nr > 0 {
					ciphertext := encrypt(buf[:nr], filecontent)
					nw, ew := w.Write(ciphertext)
					if ew != nil {
						log.Println("Write Error", ew)
						break
					}
					written += int64(nw)
				}
			}
			c <- Progress{bytes: written}

		} else {
			buf := make([]byte, 64*1024)
			var written int64 = 0
			for {
				nr, er := r.Read(buf)
				if er != nil {
					log.Println("Read Error", er)
					break
				}
				if nr > 0 {
					plaintext := decrypt(buf[:nr], filecontent)
					nw, ew := w.Write(plaintext)
					if ew != nil {
						log.Println("Write Error", ew)
						break
					}
					written += int64(nw)
				}
			}
			c <- Progress{bytes: written}
		}

	}
	if flag == 0 {
		go copy(con, os.Stdout, filecontent)
		go copy(os.Stdin, con, filecontent)
	} else {
		go copy(con, rcon, filecontent)
		go copy(rcon, con, filecontent)
	}

	p := <-c
	log.Printf("[%s]: Connection has been closed by remote peer, %d bytes has been received\n", con.RemoteAddr(), p.bytes)
	p = <-c
	log.Printf("[%s]: Local peer has been stopped, %d bytes has been sent\n", con.RemoteAddr(), p.bytes)
}

func Client(proto string, addr string, prt string, filecontent string) {
	con, err := net.Dial(proto, addr+":"+prt)
	if err != nil {
		log.Fatalln(err)
		return
	}
	log.Println("Connected to", addr+":"+prt)
	c := make(chan Progress)
	var rcon net.Conn
	TransferStreams(con, c, filecontent, rcon, 0)
}

func main() {
	var pwd string = ""
	var listen string = ""
	var addr string = ""
	var prt string = ""
	args1 := os.Args[1:]
	var ic = 0
	var sc = 0
	var bc = 0

	for i := 0; i < len(args1); i = i + 2 {
		if args1[i] == "-p" {
			if ic == 1 {
				fmt.Println("2 times -p not accepted")
				os.Exit(1)
			}
			ic = 1
			pwd = args1[i+1]
			if pwd == "-r" || pwd == "-f" || pwd == "-i" {
				fmt.Println("incorrect expression. enter value after -p")
				os.Exit(1)
			}
		} else if args1[i] == "-l" {
			if sc == 1 {
				fmt.Println("2 times -l not accepted")
				os.Exit(1)
			}
			sc = 1
			listen = args1[i+1]
			if listen == "-r" || listen == "-f" || listen == "-i" {
				fmt.Println("incorrect expression. enter value after -i")
				os.Exit(1)
			}
		} else {
			if bc == 1 {
				prt = args1[i]
				break
			}
			bc = 1
			addr = args1[i]
			i = i - 1
		}
	}
	log.Println("key =", pwd)
	log.Println("Listening on port =", listen)
	log.Println("Connecting to host address =", addr)
	log.Println("Connecting to host port =", prt)
	data, err := ioutil.ReadFile(pwd)
	if err != nil {
		return
	}
	var filecontent = ""
	filecontent = string(data)
	log.Println("key in file =", filecontent)

	if listen != "" {
		Server("tcp", listen, filecontent, addr, prt)
	} else {
		Client("tcp", addr, prt, filecontent)
	}
}
