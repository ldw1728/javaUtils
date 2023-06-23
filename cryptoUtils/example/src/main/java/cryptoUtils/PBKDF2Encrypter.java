package cryptoUtils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2Encrypter implements EncryptUtil{

    private int iterationCnt = 1234;
    private int digestLength = 256;


    public static PBKDF2Encrypter getInstance(){
        return PBKDF2Encrypter.PBKDF2Holder.instance;
    }

    static class PBKDF2Holder{
        private static final PBKDF2Encrypter instance = new PBKDF2Encrypter(); 
    }

    @Override
    public String encrypt(String str) throws Exception {
        return new String(makeHash(str, null));
    }

    @Override
    public String encrypt(String str, String salt) throws Exception {
         return new String(makeHash(str, salt));
    }

    private byte[] makeHash(String str, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException{

        byte[] saltBytes = null;

        if(salt == null || "".equals(salt)){
            saltBytes = makeTmpSaltBytes();
        }
        else{
            saltBytes = salt.getBytes();
        }

        KeySpec spec = new PBEKeySpec(str.toCharArray(), saltBytes, this.iterationCnt, this.digestLength);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        
        return factory.generateSecret(spec).getEncoded();

    }

    private byte[] makeTmpSaltBytes() throws NoSuchAlgorithmException{

        SecureRandom sr = new SecureRandom().getInstanceStrong();
        byte[] tmpSalt = new byte[16];
        sr.nextBytes(tmpSalt);

        return tmpSalt;
    }

    
    @Override
    public String decrypt(String str) throws Exception {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'decrypt'");
    }

    public void setIterationCnt(int iterationCnt) {
        this.iterationCnt = iterationCnt;
    }

    public void setDigestLength(int digestLength) {
        this.digestLength = digestLength;
    }
    
}
