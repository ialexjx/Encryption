package service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JWEService {

    public static void main(String[] args) throws Exception {
        String inputPlainText = "Hello, My name is Akshat Jaiswal";
        String cipherJWEObject = convertTextToJWEObject(inputPlainText);
        System.out.println(cipherJWEObject);
        System.out.println("Encryption Completed Going to decrypt the same object");
        String plainTextFromCipher = convertCipherToPLainText(cipherJWEObject);
        System.out.println(plainTextFromCipher);
    }

    public static String convertTextToJWEObject(String inputPlainText) throws IOException, JOSEException {
            JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM).build();
            RSAEncrypter rsaEncrypter = new RSAEncrypter((RSAPublicKey) getPublicKey());
            JWEObject jweObject = new JWEObject(jweHeader, new Payload(inputPlainText));
            jweObject.encrypt(rsaEncrypter);
            return jweObject.serialize();
    }

    public static String convertCipherToPLainText(String cipherText) throws Exception {
        RSADecrypter rsaDecrypter = new RSADecrypter(getPrivateKey());
        JWEObject jweObject = JWEObject.parse(cipherText);
        jweObject.decrypt(rsaDecrypter);
        Payload payload = jweObject.getPayload();
        return payload.toString();
    }

    public static PublicKey getPublicKey() throws IOException {
        PublicKey publicKey = null;
        String publicKeyFilePath = "/Users/alex/Workspace/Java Workspace/Encryption/data/PublicKey.pem";
        if (publicKeyFilePath == null) {
            throw new FileNotFoundException("Public key file not found");
        }

        String publicKeyPem = new String(Files.readAllBytes(Paths.get(publicKeyFilePath)));
        try {
            String publicKeyPEMContent = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            // Decode the Base64-encoded string
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEMContent);

            // Create a PublicKey object from the byte array
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
        return publicKey;
    }

    public static PrivateKey getPrivateKey() throws Exception {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("PrivateKey.pem");
        if (inputStream == null) {
            throw new FileNotFoundException("Private key file not found");
        }

        String privateKeyPEM = new String(inputStream.readAllBytes());
        privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
        privateKeyPEM = privateKeyPEM.replaceAll("\\s+", "");

        byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyDER);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
}
