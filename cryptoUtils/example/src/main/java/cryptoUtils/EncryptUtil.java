package cryptoUtils;

public abstract class EncryptUtil {
    abstract String encrypt(String str) throws Exception;
    abstract String encrypt(String str, String salt) throws Exception;
    abstract String decrypt(String str) throws Exception; 
}
