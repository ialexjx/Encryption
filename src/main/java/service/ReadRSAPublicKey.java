package service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ReadRSAPublicKey {
    public static PublicKey getPublicKey() throws IOException {
        String publicKeyPath = "/Users/alex/Workspace/Java Workspace/Encryption/data/PublicKey.pem";
        String publicKeyPEM = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
        PublicKey publicKey = null;

        try {
            String publicKeyPEMContent = publicKeyPEM
                    .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEMContent);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
