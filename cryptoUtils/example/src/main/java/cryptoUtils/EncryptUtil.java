package cryptoUtils;

public interface EncryptUtil {
    public String encrypt(String str) throws Exception;
    public String encrypt(String str, String salt) throws Exception;
    public String decrypt(String str) throws Exception; 
}
