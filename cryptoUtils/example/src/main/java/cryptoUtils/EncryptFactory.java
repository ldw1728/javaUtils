package cryptoUtils;

public class EncryptFactory {
    public static EncryptUtil getEncrypt(String encName){
        switch(encName){
            case "RSA" : 
                return RSAEncrypter.getInstance(); 
            case "AES" : 
                return AESEncrypter.getInstance();
            case "SHA" : 
                return SHAEncrypter.getInstance();
            case "PBKDF2" :
                return PBKDF2Encrypter.getInstance();
        }
        return null;
    }
}
