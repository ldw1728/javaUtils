package cryptoUtils;

public class EncryptFactory {
    public static EncryptUtil getEncrypt(String encName){
        switch(encName){
            case "RSA" : 
                return RSAUtil.getInstance(); 
            case "AES" : 
                return AESUtil.getInstance();
            case "SHA" : 
                return SHAUtil.getInstance();
        }
        return null;
    }
}
