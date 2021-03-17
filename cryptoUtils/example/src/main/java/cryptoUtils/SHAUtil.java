package cryptoUtils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SHAUtil {
    //암호화 + 솔트
    public static String encrypt(String str, String salt) throws NoSuchAlgorithmException{
        byte[] hashingData = hashingString(str + salt);
        return byteToHexString(hashingData);
    }
    //암호화
    public static String encrypt(String str) throws NoSuchAlgorithmException{
        byte[] hashingData = hashingString(str);
        return byteToHexString(hashingData);
    }
    //문자열 해싱
    private static byte[] hashingString(String str) throws NoSuchAlgorithmException{
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(str.getBytes());
        return md.digest();
    }
    //바이트배열을 16진수 문자열로
    private static String byteToHexString(byte[] byteData){
        StringBuilder sb = new StringBuilder();
        for(byte b : byteData){ 
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    //랜덤 솔트 생성
    public static String getRandomSalt() throws NoSuchAlgorithmException{
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] saltByte = new byte[16];
        sr.nextBytes(saltByte); 

        return byteToHexString(saltByte);
    }
}
