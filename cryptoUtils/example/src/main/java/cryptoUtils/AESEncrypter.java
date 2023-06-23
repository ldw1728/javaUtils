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
import javax.crypto.spec.SecretKeySpec;

public class AESEncrypter implements EncryptUtil{

    private static final String key = "qwertasdfg123456"; //고정키

    private Cipher cipher;
    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParam;

    public AESEncrypter() { }

    public static AESEncrypter getInstance(){
        return AESHolder.instance;
    }

    public void init(boolean dynamicUse) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
        cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        createKey(dynamicUse);
    }
    private void createKey(boolean dynamicUse) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        byte[] keyBytes = null;

        if(dynamicUse == true){ //동적 키 사용
            KeyGenerator kg = KeyGenerator.getInstance("AES"); // 대칭키 생성을 위한 generator(대칭키를 위한 seceretKey 생성하는 엔진클래스)
            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); //
            // 랜덤 키를 생성하기 위한 클래스, 혹은 임의로 지정해서 사용가능

            kg.init(128, sr);
            Key secureKey = kg.generateKey();
            keyBytes = secureKey.getEncoded();
        }
        else{ //고정 키 사용
            keyBytes = key.getBytes("UTF-8");
        }

        secretKeySpec = new SecretKeySpec(keyBytes, "AES");

        ivParam = new IvParameterSpec(keyBytes);
        // CBC모드에 필요한 Init Value Param
    }

    //암호화
    @Override
    public String encrypt(String str) throws InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParam);
        byte[] encryptData = cipher.doFinal(str.getBytes("UTF-8"));
        String encStr = new String(Base64.getEncoder().encodeToString(encryptData));
        
        return encStr;
    }
    //복호화
    @Override
    public String decrypt(String str) throws InvalidKeyException, InvalidAlgorithmParameterException,
            UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParam);
        byte[] decryptData = Base64.getDecoder().decode(str);
        String decStr = new String(cipher.doFinal(decryptData),"UTF-8");

        return decStr;
    }

    //key getter
    public SecretKeySpec getsecretKeySpec(){
        return this.secretKeySpec;
    }
   
    public static class AESHolder{
        private static final AESEncrypter instance = new AESEncrypter();
    }


    @Override
    public String encrypt(String str, String salt) throws Exception {
        // TODO Auto-generated method stub
        return null;
    }

}
