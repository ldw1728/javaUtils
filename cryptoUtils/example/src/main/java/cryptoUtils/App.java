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
     * @throws Exception
     */
    public static void main(String[] args) throws Exception {

        // SHA암호화 예제.
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


            // String str = "안녕하세요 이동욱입니다.";
            // System.out.println(str);
            // SHAUtil sha = (SHAUtil)EncryptFactory.getEncrypt("SHA");

            // //rsa.generateKeyPair();
            // String salt = sha.getRandomSalt();
            // // 같은 문자열이라도 솔트값에 따라 암호화문자열이 달라짐.
            // // 암호화할때마다 랜덤솔트함수를 사용하여 솔트값을 사용할 시 솔트값을 따로 저장해놓거나
            // //랜덤솔트함수를 사용하여 고정 솔트를 지정하여 사용한다. 

            // System.out.println(salt);

            // String encStr = sha.encrypt(str, salt);

            // System.out.println(encStr);

            //AES 암호화 예제.
            // AESUtil AESUtil = (cryptoUtils.AESUtil) EncryptFactory.getEncrypt("AES");

            // AESUtil.init(false);// 초기화. param : 동적키, 고정키사용 여부

            // String str = "안녕하세요 이동욱입니다.";

            // System.out.println("문자열 : " + str);

            // String encStr = AESUtil.encrypt("안녕하세요 이동욱입니다.");

            // System.out.println("암호화 : "+encStr);

            // String decStr = AESUtil.decrypt(encStr);

            // System.out.println("복호화 : " + decStr);

            //RSA
            // RSAUtil rsaUtil = (RSAUtil) EncryptFactory.getEncrypt("RSA");
            // //rsaUtil.generateKeyPair();
            // rsaUtil.init();
            // String str = "안녕하세요 이동욱입니다.";
            // String encStr = rsaUtil.encrypt(str);
            // System.out.println("개인키 : " + rsaUtil.getPrivateKey());
            // System.out.println("공개키 : " + rsaUtil.getPublicKey());
            // System.out.println("공개키를 이용한 암호화 : "+ encStr);
            // //rsaUtil.init(); //키를 다시생성하여 복호화할 경우 개인키가 달라지므로 에러가 발생.
            // System.out.println("복호화 : " + rsaUtil.decrypt(encStr));
            

            EncryptUtil pbkd = EncryptFactory.getEncrypt("PBKDF2");
            System.out.println(pbkd.encrypt("wooklee"));

            
            
    }
}
