
import com.mkyong.crypto.utils.CryptoUtils;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;
import javax.crypto.KeyAgreement;
import java.util.*;
import java.nio.ByteBuffer;
import java.io.Console;
import com.mkyong.crypto.utils.CryptoUtils;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
 
public class Server {
    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128; // must be one of {128, 120, 112, 104, 96}
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    
    public static void main (String[] args) throws Exception{
        //Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();
        
        // Iterating through each byte in the array to convert from bit array to string
        String serverPublic = "";
        for (byte i : ourPk) {
            serverPublic += String.format("%02X", i);
        }

        // Display our public key
        System.out.println("Server Public Key: ");
        System.out.println(serverPublic + "\n");
              
        //Server is now live
        try {
            ServerSocket serversocket = new ServerSocket(8888);
            System.out.println("Waiting For Client...");
            Socket socket = serversocket.accept();
            System.out.println("Connection Request Accepted");
            
            //Initializing printer and reader
            PrintStream ps = new PrintStream(socket.getOutputStream());
            BufferedReader bs = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            
            //sending public key
            ps.println(serverPublic);
            ps.flush();
            System.out.println("Response from Client.....\n");
            
            //Reading and Sending Public Key
            String clientPublic = bs.readLine();
            System.out.println("Public Key Recieved\nClient Public Key: ");
            System.out.println(clientPublic + "\n");
            
            //converting to bit array
            byte[] clientPKEY = new byte[clientPublic.length() / 2];

            for (int i = 0; i < clientPKEY.length; i++) {
               int index = i * 2;
               // Using parseInt() method of Integer class
               int val = Integer.parseInt(clientPublic.substring(index, index + 2), 16);
               clientPKEY[i] = (byte)val;
            }
           
            //initializes eliptic curve encode scheme?
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(clientPKEY);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);
           
            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(otherPublicKey, true);
            
            // Read shared secret, converts from bit array to string
            byte[] sharedSecret = ka.generateSecret();
            String sharedSecretStr = "";
            for (byte i : sharedSecret) {
            sharedSecretStr += String.format("%02X", i);
            }
            System.out.println("Shared Secret: \n" + sharedSecretStr + "\n");

              
            // Derive a key from the shared secret and both public keys
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedSecret);
            // Simple deterministic ordering
            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(clientPKEY));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));
            byte[] derivedKey = hash.digest();
            //Converts String from bit array to string so we can read it
            String derivedKeyStr = "";
            for (byte i : derivedKey) {
               derivedKeyStr += String.format("%02X", i);
            }
            System.out.println("DerivedKey: \n" + derivedKeyStr + "\n");
            
            //Reading Client Message (decryption happens before here)
            String encryptedTextBase64 = bs.readLine();
            System.out.println("Client Message Encrypted: " + encryptedTextBase64 + "/n");
            String decryptedText = Server.decrypt(encryptedTextBase64, derivedKeyStr);
            System.out.println("Client Message: " + decryptedText);
            
            //closing socket
            socket.close();
            serversocket.close();
        }
        catch (IOException e) {
            System.out.println("Socket Data Not Found" + e);
        }
    }
    
    private static String decrypt(String cText, String password) throws Exception {
      System.out.println("\nDecryption Start...");
      byte[] decode = Base64.getDecoder().decode(cText.getBytes(UTF_8));
    
      // get back the iv and salt from the cipher text
      ByteBuffer bb = ByteBuffer.wrap(decode);
      byte[] iv = new byte[IV_LENGTH_BYTE];
      bb.get(iv);
    
      byte[] salt = new byte[SALT_LENGTH_BYTE];
      bb.get(salt);
      byte[] cipherText = new byte[bb.remaining()];
      bb.get(cipherText);
    
      // get back the aes key from the same password and salt
      SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);
    
      Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
    
      cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
    
      byte[] plainText = cipher.doFinal(cipherText);
      System.out.println("Decryption Finish!\n");
      return new String(plainText, UTF_8);
    
    }
}