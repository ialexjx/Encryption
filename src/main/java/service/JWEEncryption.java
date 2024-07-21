package service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;

public class JWEEncryption {

    private static final String ENCRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static void main(String[] args) throws Exception {
        PrivateKey privateKey = ReadRSAPrivateKey.getPrivateKey();

        String plainText = "Hello there !! I'm a plain text";
        byte[] encodedBytes = Base64.getEncoder().encode(plainText.getBytes());

        Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] cipherBytes = cipher.doFinal(encodedBytes);

        System.out.println(new String(cipherBytes, StandardCharsets.UTF_8));
    }

}
