# Plugboard_proxy
Plugboard proxy for adding an extra layer of protection to publicly accessible network services.

The plugboard proxy program implemented using golang adds an extra layer of encryption to connections towards TCP services.
Instead of connecting directly to the service, clients connect to pbproxy, which then relays all traffic to the actual service.

With this program multiple clients can connect to the server at once and run parallelly.

The implementation can be easily understood if thought of it as running in 2 modes: Server and Client.
_______________________________________________________________________________________________________________________________
-> Server Mode

Specification
sudo go run pbproxy.go -p pwd.txt -l 2222 localhost 12345

Usage:
The code takes 3 parameters

1) -p encryption key.
This is a file which will contain the encryption key for the encryption and decryption through AES. If no file is provided, then a default
key is used.

2) -l port on which listen to
The port to which the client will connect to.

3) Host and port to connect to
The host address and port number to which pbproxy program will forward the message in plaintext after decrypting the message from the 
client. And the other way round.

The program needs to run in sudo to avoid permission related errors.

Implementation Details:
Once all the parameters are gathered from the command line arguments, the Server functionality is called and it works in the following 
manner:
- The server listens to the specified port using the net.listen function.
- All the connection requestes are accepted and a connection is established using the net.dial function.
- After that the connection is handled by the transferstrams funtion.
- TransferStreams launches two read-write goroutines and waits for messages from them.
- The salt and the nonce are randomly generated.
- Once message is received, it is decrypted using the specified key and converted to plaintext.
- The plaintext is sent to the address and port specified by the user.
- Data from the server is encrypted and is sent to the client.

-> Client Mode
Specification
sudo go run pbproxy.go -p pwd.txt 192.168.2.128 2222

Usage:
The code takes 3 parameters

1) -p encryption key.
This is a file which will contain the encryption key for the encryption and decryption through AES. If no file is provided, then a default
key is used.

2) Host and port to connect to
The host address and port number to which pbproxy program will forward the message in after encrypting the message from the stdin. And the 
other way round.

The program needs to run in sudo to avoid permission related errors.

Implementation Details:
Once all the parameters are gathered from the command line arguments, the Client functionality is called and it works in the following 
manner:
- Connection is established using the net.dial function.
- After that the connection is handled by the transferstrams funtion.
- TransferStreams launches two read-write goroutines and waits for messages from them.
- For the client mode the transferstream reads and writes data to the stdin/stdout.
- The plaintext from the stdin is encrypted while the received messages are decrypted and printed.
- The salt and the nonce are randomly generated.
_______________________________________________________________________________________________________________________________


Clients can then connect to the SSH server using the following command:
ssh -o "ProxyCommand go run pbproxy.go -p pwd.txt address port" localhost
- The port number should be the port on which the plugboardproxy program is listening.

Output:
-> While using as Plugboard proxy
- sudo go run pbproxy.go -p pwd.txt -l 2222 localhost 22       (server side)
2021/05/01 15:19:17 key = pwd.txt
2021/05/01 15:19:17 Listening on port = 2222
2021/05/01 15:19:17 Connecting to host address = localhost
2021/05/01 15:19:17 Connecting to host port = 22
2021/05/01 15:19:17 key in file = this is a pwd
2021/05/01 15:19:17 Listening  tcp:2222
2021/05/01 15:19:21 [192.168.2.129:45466]: Connection opened
2021/05/01 15:19:21 Connected  localhost:22

- ssh -o "ProxyCommand go run pbproxy.go -p pwd.txt 192.168.2.128 2222" localhost       (Client side)
2021/05/01 18:19:21 key = pwd.txt
2021/05/01 18:19:21 Listening on port = 
2021/05/01 18:19:21 Connecting to host address = 192.168.2.128
2021/05/01 18:19:21 Connecting to host port = 2222
2021/05/01 18:19:21 key in file = this is a pwd
2021/05/01 18:19:21 Connected to 192.168.2.128:2222
sneh@localhost's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.8.0-48-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

117 updates can be installed immediately.
31 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Your Hardware Enablement Stack (HWE) is supported until April 2025.
Last login: Sat May  1 15:18:53 2021 from 127.0.0.1
sneh@ubuntu:~$ 

-> While using as client-side proxy and as server-side reverse proxy.
- nc -l -p 12345
hello
hi
sending this message from client
sending this message from server

- sudo go run pbproxy.go -p pwd.txt -l 2222 localhost 12345
2021/05/01 15:31:14 key = pwd.txt
2021/05/01 15:31:14 Listening on port = 2222
2021/05/01 15:31:14 Connecting to host address = localhost
2021/05/01 15:31:14 Connecting to host port = 12345
2021/05/01 15:31:14 key in file = this is a pwd
2021/05/01 15:31:14 Listening  tcp:2222
2021/05/01 15:31:26 [192.168.2.129:45484]: Connection opened
2021/05/01 15:31:26 Connected  localhost:12345

- sudo go run pbproxy.go -p pwd.txt 192.168.2.128 2222                
[sudo] password for sneh: 
2021/05/01 18:31:26 key = pwd.txt
2021/05/01 18:31:26 Listening on port = 
2021/05/01 18:31:26 Connecting to host address = 192.168.2.128
2021/05/01 18:31:26 Connecting to host port = 2222
2021/05/01 18:31:26 key in file = this is a pwd
2021/05/01 18:31:26 Connected to 192.168.2.128:2222
hello
hi
sending this message from client
sending this message from server

References:
https://github.com/dddpaul/gonc
https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial/
https://golang.org/src/io/io.go
https://pkg.go.dev/golang.org/x/crypto/pbkdf
