<h1>AES-GCM Message Sender</h1>


<h2>Description</h2>
This project is a Java TCP socket program that uses ECDH (Elliptic-Curve Diffie-Helman) and AES-GCM to send an encrypted message from a client to a server. The client and server will use ECDH to derive a key. Once the key is derived, the client  will prompt the user for a message to send to the server. The client will encrypt this message using AES-GCM encryption and send the message to the server. The server will then use AES-GCM to decrypt the message and display the decrypted message to the terminal. This project was completed in a team environment, with all members contributing to both client and server applications. 
<br />


<h2>Languages and Utilities Used</h2>

- <b>Java</b> 
- <b> mkyong AES-GCM algorithm </b>
  - [mkyong](https://github.com/mkyong/core-java/tree/master/java-crypto/src/main/java/com/mkyong/crypto)
- <b> Neil Madden ECDH algorithm </b>
  - [Neil Madden ECDH](https://neilmadden.blog/2016/05/20/ephemeral-elliptic-curve-diffie-hellman-key-agreement-in-java/#more-2269)

<h2>Environments Used </h2>

- <b>Windows 10</b>
- <b>VS Code</b>

<h2>Project walk-through:</h2>
<p align="center">
  Compilation and Execution (Windows Terminal): <br/>
  <img src="https://imgur.com/cuv1jwO.png" height="90%" width="90%" alt="Disk Sanitization Steps"/>
  <br />
  <br />
  Enter User input:
  <img src="https://imgur.com/DROXoVu.png" height="90%" width="90%" alt="Disk Sanitization Steps"/>
</p>

