package service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;

public class Decryption {
    private static final String DECRYPTION_ALGORITHM = "RSA/ECB/PKCS1Padding";

    public static void main(String[] args) throws Exception {
        PrivateKey privateKey = ReadRSAPrivateKey.getPrivateKey();
        String encryptedBase64Text = "d7HLy+eA3+GAAVLAsW02lcPVWaaoeJV4t9gDr9nJLCe9Mn6STqwpqjrnW56Gjc3xqlr8O8jU+GhoMRfmsyegvjeE9DrrtyQdw9qJC78E60Z4b3U0l+CPYUfR7tLS4rnm/TSGhgz9DfCd9oPgeHt7HUlsQbnXHroopnXxUxxoTYLd48lF4w+DWY1JXmZtM/6u/FwDRGPjs8SPSSQeCs/d3zm3urpvZwxwLhxOv2SFWCXxl1Y4EFpSgnjnrYJ96y03RQFytphwKFdfsl2HQGhu9ptOSCBuwCyyKOFRzKdmFERdXRJr3nJn22PmMc8Nur14pjqQSfLzk6eqrwU3SNKHKA==";
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedBase64Text);

        Cipher cipher = Cipher.getInstance(DECRYPTION_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(decodedBytes);

        System.out.println(new String(decryptedBytes, StandardCharsets.UTF_8));
    }


}
