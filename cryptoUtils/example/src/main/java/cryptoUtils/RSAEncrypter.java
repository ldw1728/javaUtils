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

public class RSAEncrypter implements EncryptUtil{

    private final static int KEY_SIZE = 1024; //일반적으로 1024이상이 쓰여진다. 보안상.

    private Cipher cipher; //암호화/복호화를 담당하는 클래스 
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;
    private KeyFactory kf;
    private RSAPublicKeySpec publicSpec;
    
    public RSAEncrypter(){
        try {

            this.cipher = Cipher.getInstance("RSA"); //알고리즘을 선택하여 인스턴스를 가져온다.
            this.kf = KeyFactory.getInstance("RSA");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {            
            e.printStackTrace();
        }
    }

    public static RSAEncrypter getInstance(){
        return RSAHolder.instance;
    }

    public static class RSAHolder{
        private static final RSAEncrypter instance = new RSAEncrypter();
    }

    
    public void init(RSAPrivateKey privateKey, RSAPublicKey publicKey){
       this.privateKey = privateKey;
       this.publicKey = publicKey;
       try {
        publicSpec = kf.getKeySpec(this.publicKey, RSAPublicKeySpec.class);
    } catch (InvalidKeySpecException e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
    }
    }

    //키 초기화
    public void init(){       
            generateKeyPair(); // 키 새로생성.            
        try {
            publicSpec = kf.getKeySpec(this.publicKey, RSAPublicKeySpec.class);
        } catch (InvalidKeySpecException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    //키 생성
    /**
     * generateKeyPair를 호출시 개인키와 공개키를 생성.
     * 개인키는 서버에, 공개키는 클라이언트에 보관.
     */
    private void generateKeyPair(){
        try {
             
            //Security.addProvider(new BouncyCastleProvider());
            //확장된 기능을 가진 암호 라이브러리 BouncyCastleProvider

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); //비대칭키 생성을 위한 keyPairGenerator(공개키, 개인키 같은 키쌍을 생성할때 사용되는 엔진.)
            keyGen.initialize(KEY_SIZE);

            KeyPair keyPair = keyGen.generateKeyPair(); //키 쌍 객체 생성.
            
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate(); //개인키 생성.
            this.publicKey = (RSAPublicKey) keyPair.getPublic(); //공개키 생성.

        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } 
    }

    //암호화
    @Override
    public String encrypt(String str) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        if(this.publicKey == null || "".equals(this.publicKey)){
            return "";
        }
        return encrypt_temp(str, this.publicKey);
    }

    public String encrypt(String str, RSAPublicKey publicKey) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
        return encrypt_temp(str, publicKey);
    }

    private String encrypt_temp(String str, RSAPublicKey publicKey ) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
        
        String result = "";
        try{
            cipher.init(Cipher.ENCRYPT_MODE, publicKey); //암호화모드
            byte[] encryptBytes = cipher.doFinal(str.getBytes("UTF-8"));
            result = new String(Base64.getEncoder().encodeToString(encryptBytes));

        }catch(Exception e){
            e.printStackTrace();
        }finally{
            return result;
        }              
    }

    //복호화
    @Override
    public String decrypt(String str) throws NoSuchAlgorithmException, 
    NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, 
    IllegalBlockSizeException, BadPaddingException{
        if(this.privateKey == null || "".equals(this.privateKey)){
            return "";
        }
        return decrypt_temp(str, this.privateKey);
    }

    public String decrypt(String str, RSAPrivateKey privateKey) throws NoSuchAlgorithmException, 
    NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, 
    IllegalBlockSizeException, BadPaddingException{
        return decrypt_temp(str, privateKey);
    }

    private String decrypt_temp(String str, RSAPrivateKey privateKey) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
        String result = "";
        try{
            cipher.init(Cipher.DECRYPT_MODE, privateKey); //복호화모드
            byte[] decryptBytes = Base64.getDecoder().decode(str.getBytes());
            result = new String(cipher.doFinal(decryptBytes), "UTF-8");
        }catch(Exception e){
            e.printStackTrace();
        }finally{
            return result;
        }
        
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
    public RSAPublicKey getPublicKey(BigInteger modulus, BigInteger exponent) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
        return (RSAPublicKey) kf.generatePublic(keySpec);
    }

    //publickey "MODULUS", "EXPONENT" 가져오기
    public String getPublicKey_elements(String name){
        if(this.publicSpec != null){
            if("MODULUS".equals(name)){
                return publicSpec.getModulus().toString(16);
            }
            else if("EXPONENT".equals(name)) 
                return publicSpec.getPublicExponent().toString(16);          
        }
            return null;       
    }

    @Override
    public String encrypt(String str, String salt) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'encrypt'");
    }

    
}
/**
 * 서버와 클라이언트 rsa동작
 * 서버에서 Public key, private key 생성
 * public key를 이용하여 modulus, exponent 생성 및 front로 전송.
 * front에서는 서버로 부터 modulus, exponent값을 받아와 
 * js로 RSA공개키를 생성하고 데이터를 암호화를 하여 암호화된 데이터를 서버로 보낸다.
 * 서버는 session에 저장된 개인키를 이용하여 복호화한다.
 */
