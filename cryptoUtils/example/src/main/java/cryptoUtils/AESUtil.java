package cryptoUtils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class AESUtil {
    private Cipher cipher;
    private Key secureKey;
    private IvParameterSpec ivParam;

    public AESUtil() throws NoSuchAlgorithmException, NoSuchPaddingException {
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        createKey();
    }

    private void createKey() throws NoSuchAlgorithmException {
        KeyGenerator kg = KeyGenerator.getInstance("AES"); // 대칭키 생성을 위한 generator
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); //
        // 랜덤 키를 생성하기 위한 클래스, 혹은 임의로 지정해서 사용가능

        // String key = "qwertasdfg123456";
        // SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
        // 지정키 사용시 SecretKeySpec객체 생성.
        kg.init(128, sr);
        secureKey = kg.generateKey();

        ivParam = new IvParameterSpec(sr.generateSeed(16));
        // CBC모드에 필요한 Init Value Param

    }
    //암호화
    public String encrypt(String str) throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        
        cipher.init(Cipher.ENCRYPT_MODE, secureKey, ivParam);
        byte[] encryptData = cipher.doFinal(str.getBytes("UTF-8"));
        String encStr = new String(Base64.getEncoder().encodeToString(encryptData));
        
        return encStr;
    }
    //복호화
    public String decrypt(String str) throws InvalidKeyException, InvalidAlgorithmParameterException,
            UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, secureKey, ivParam);
        byte[] decryptData = Base64.getDecoder().decode(str);
        String decStr = new String(cipher.doFinal(decryptData),"UTF-8");

        return decStr;
    }
   


}
