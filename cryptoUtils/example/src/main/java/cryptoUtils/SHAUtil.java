package cryptoUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SHAUtil extends EncryptUtil{

    public static SHAUtil getInstance(){
        return SHAHolder.instance;
    }
    
    //암호화 + 솔트
    @Override
    public String encrypt(String str, String salt) throws NoSuchAlgorithmException{
        byte[] hashingData = hashingString(str + salt);
        return byteToHexString(hashingData);
    }
    //암호화
    @Override
    public String encrypt(String str) throws NoSuchAlgorithmException{
        byte[] hashingData = hashingString(str);
        return byteToHexString(hashingData);
    }
    //문자열 해싱   
    private byte[] hashingString(String str) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(str.getBytes());
        return md.digest();
    }
    //바이트배열을 16진수 문자열로
    private String byteToHexString(byte[] byteData){
        StringBuilder sb = new StringBuilder();
        for(byte b : byteData){ 
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    //랜덤 솔트 생성
    public String getRandomSalt() throws NoSuchAlgorithmException{
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] saltByte = new byte[16];
        sr.nextBytes(saltByte); 

        return byteToHexString(saltByte);
    }

    public static class SHAHolder{
        private static final SHAUtil instance = new SHAUtil();
    }

    @Override
    String decrypt(String str) throws Exception {
        // TODO Auto-generated method stub
        return null;
    }
}
