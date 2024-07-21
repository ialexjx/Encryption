package service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class ReadRSAPrivateKey {
    public static PrivateKey getPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyFilePath = "/Users/alex/Workspace/Java Workspace/Encryption/data/PrivateKey.pem";
        String privateKeyPem = new String(Files.readAllBytes(Paths.get(privateKeyFilePath)));

        privateKeyPem = privateKeyPem.replace("-----BEGIN RSA PRIVATE KEY-----", "");
        privateKeyPem = privateKeyPem.replace("-----END RSA PRIVATE KEY-----", "");
        privateKeyPem = privateKeyPem.replaceAll("\\s+", "");

        byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPem);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyDER);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        System.out.println("Successfully fetched the private key");
        return privateKey;
    }
}
