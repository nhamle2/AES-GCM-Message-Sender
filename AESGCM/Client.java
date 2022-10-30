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
 
public class Client {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128; // must be one of {128, 120, 112, 104, 96}
    private static final int IV_LENGTH_BYTE = 12;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;

    public static void main(String[] args) throws Exception {
    
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();
        
        // Iterating through each byte in the array to convert to string
        String clientPublic = "";
        for (byte i : ourPk) {
            clientPublic += String.format("%02X", i);
        }
  
        // Display client public key
        System.out.println("Client Public Key: ");
        System.out.println(clientPublic + "\n");
        
        //Client is now live
        try {
            System.out.println("Waiting To Connect...");
            Socket socket = new Socket("localhost", 8888);
            System.out.println("Connection Successful\n");
 
            //initializing printer and reader
            PrintStream ps = new PrintStream(socket.getOutputStream());
            BufferedReader bs = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            
            //sending public key
            ps.println(clientPublic);
            ps.flush();
            
            //reading public key in String format
            String serverPublic = bs.readLine();
            System.out.println("Public Key Recieved\nServer Public Key: ");
            System.out.println(serverPublic + "\n");
            
            //converting to bit array
            byte[] serverPKEY = new byte[serverPublic.length() / 2];
            for (int i = 0; i < serverPKEY.length; i++) {
               int index = i * 2;
               // Using parseInt() method of Integer class
               int val = Integer.parseInt(serverPublic.substring(index, index + 2), 16);
               serverPKEY[i] = (byte)val;
            }
           
            //initializes eliptic curve encode scheme
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(serverPKEY);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);
           
            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(otherPublicKey, true);
            
            //Read shared secret, converts from bit array to string
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
            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(serverPKEY));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));
            byte[] derivedKey = hash.digest();
            
            //Converts String from bit array to String so we can read it
            String derivedKeyStr = "";
            for (byte i : derivedKey) {
               derivedKeyStr += String.format("%02X", i);
            }
            System.out.println("DerivedKey: \n" + derivedKeyStr + "\n");

            //to be encrypted then sent to server
            System.out.println("Input Message To Be Send To The Server");
            String message = br.readLine();
            
            String encryptedTextBase64 = Client.encrypt(message.getBytes(UTF_8), derivedKeyStr);
            System.out.println("\nEncrypted Message:" + encryptedTextBase64);
           
            //encrypt MESSAGE HAS TO BE CONVERTED TO BYTE ARRAY[]
            ps.println(encryptedTextBase64);
            System.out.println("Message Sent To Server!");
            
            //closing socket
            socket.close();
        }
        catch (UnknownHostException e) {
            System.out.println("IP not found for" + e);
        }
        catch (IOException e) {
            System.out.println("Not found data for socket" + e);
        }
    }
    
    public static String encrypt(byte[] pText, String password) throws Exception {
        System.out.println("\nEncryption Start...");


        // 16 bytes salt
        byte[] salt = CryptoUtils.getRandomNonce(SALT_LENGTH_BYTE);

        // GCM recommended 12 bytes iv?
        byte[] iv = CryptoUtils.getRandomNonce(IV_LENGTH_BYTE);

        // secret key from password
        SecretKey aesKeyFromPassword = CryptoUtils.getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        // ASE-GCM needs GCMParameterSpec
        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] cipherText = cipher.doFinal(pText);

        // prefix IV and Salt to cipher text
        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();

        // string representation, base64, send this string to other for decryption.
        System.out.println("Encryption Finish!!");
        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);

    }
}

