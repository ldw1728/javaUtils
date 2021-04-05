package cryptoUtils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Hello world!
 */
public final class App {
    private App() {
    }

    /**
     * Says hello to the world.
     * @param args The arguments of the program.
     * @throws UnsupportedEncodingException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     */
    public static void main(String[] args) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
        // try {
        //     AESUtil aes = AESUtil.getInstance();
        //     aes.init();
        //     String str = aes.encrypt("안녕하세요");
        //     System.out.println("안녕하세요");
        //     System.out.println(str);
        //     str = aes.decrypt(str);
        //     System.out.println(str);
            
        //     String salt1 = SHAUtil.getRandomSalt();
        //     String salt2 = SHAUtil.getRandomSalt();
        //     System.out.println("이동욱입니다." + " => " + SHAUtil.encrypt("이동욱입니다.", salt1));
        //     System.out.println("이동욱입니다." + " => " + SHAUtil.encrypt("이동욱입니다.", salt2));

		// } catch (NoSuchAlgorithmException e) {
		// 	// TODO Auto-generated catch block
		// 	e.printStackTrace();
		// } catch (NoSuchPaddingException e) {
		// 	// TODO Auto-generated catch block
		// 	e.printStackTrace();
		// }
            String str = "안녕하세요 이동욱입니다.";
            System.out.println(str);
            SHAUtil sha = (SHAUtil)EncryptFactory.getEncrypt("SHA");

            //rsa.generateKeyPair();
            String salt = sha.getRandomSalt();
            String encStr = sha.encrypt(str, salt);

            System.out.println(encStr);

            
            

    }
}
