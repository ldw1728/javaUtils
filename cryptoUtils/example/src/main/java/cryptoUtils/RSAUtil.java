package cryptoUtils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSAUtil extends EncryptUtil{

    private final static int KEY_SIZE = 1024; //일반적으로 1024이상이 쓰여진다. 보안상.

    private Cipher cipher;
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public static RSAUtil getInstance(){
        return RSAHolder.instance;
    }

    public static class RSAHolder{
        private static final RSAUtil instance = new RSAUtil();
    }

    //키 생성
    public void generateKeyPair(){
        try {
             
            //Security.addProvider(new BouncyCastleProvider());
            //확장된 기능을 가진 암호 라이브러리 BouncyCastleProvider

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); //비대칭키 생성을 위한 keyPairGenerator
            keyGen.initialize(KEY_SIZE);

            KeyPair keyPair = keyGen.generateKeyPair();
            
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate(); //개인키 생성.
            this.publicKey = (RSAPublicKey) keyPair.getPublic(); //공개키 생성.

        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 
    }

    //암호화
    @Override
    public String encrypt(String str) throws NoSuchAlgorithmException,
     NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, UnsupportedEncodingException{

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] encryptBytes = cipher.doFinal(str.getBytes("UTF-8"));
        return new String(Base64.getEncoder().encodeToString(encryptBytes));
    }
    //복호화
    @Override
    public String decrypt(String str) throws NoSuchAlgorithmException, 
    NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, 
    IllegalBlockSizeException, BadPaddingException{

        cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] decryptBytes = Base64.getDecoder().decode(str.getBytes());
        return new String(cipher.doFinal(decryptBytes), "UTF-8");
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    //client의 공개키 정보를 받아와 publickey생성
    public void setPublicKey(BigInteger modulus, BigInteger exponent) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        this.publicKey = (RSAPublicKey) kf.generatePublic(keySpec);
    }

    @Override
    String encrypt(String str, String salt) throws Exception {
        // TODO Auto-generated method stub
        return null;
    }

    
}
