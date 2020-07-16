package AES;


import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.*;
import java.security.*;

public class AES {
    public static final String IV  = "1ci5crnda6ojzgtr";//向量i
	/**
	 * AES加密字符串
	 * 
	 * @param content
	 *            需要被加密的字符串
	 * @param password
	 *            加密需要的密码
	 * @return 密文
	 */
	public static byte[] encrypt(String content, String password) throws InvalidAlgorithmParameterException {
	    KeyGenerator kgen = null;
	    try {
	        kgen = KeyGenerator.getInstance("AES");
	        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(password.getBytes());
			kgen.init(128, secureRandom);
			SecretKey secretKey = kgen.generateKey();
	        byte[] enCodeFormat = secretKey.getEncoded();
	        SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
	       // Cipher cipher = Cipher.getInstance("AES");// 创建密码器
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                 IvParameterSpec ips = new IvParameterSpec(IV.getBytes());
	        cipher.init(Cipher.ENCRYPT_MODE, key,ips);// 初始化
	        byte[] byteContent = content.getBytes("utf-8");
	        byte[] result = cipher.doFinal(byteContent);
	        return result;//加密
	    } catch (NoSuchAlgorithmException | InvalidKeyException
	            | NoSuchPaddingException | BadPaddingException
	            | UnsupportedEncodingException | IllegalBlockSizeException e) {
	        e.printStackTrace();
	    }
	    return null;
	}

	/**
	 * 解密AES加密过的字符串
	 * 
	 * @param content
	 *            AES加密过过的内容
	 * @param password
	 *            加密时的密码
	 * @return 明文
	 */
	public static byte[] decrypt(byte[] content, String password) throws InvalidAlgorithmParameterException {
	    KeyGenerator kgen = null;
	    try {
	        kgen = KeyGenerator.getInstance("AES");
	        SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
			secureRandom.setSeed(password.getBytes());
			kgen.init(128, secureRandom);
			SecretKey secretKey = kgen.generateKey();
	        byte[] enCodeFormat = secretKey.getEncoded();
	        SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
	        //Cipher cipher = Cipher.getInstance("AES");// 创建密码器
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");  
                IvParameterSpec iv = new IvParameterSpec(IV.getBytes()); 
	        cipher.init(Cipher.DECRYPT_MODE, key,iv);// 初始化
	        byte[] result = cipher.doFinal(content);
	        return result; // 解密
	    } catch (NoSuchAlgorithmException | BadPaddingException
	            | IllegalBlockSizeException | NoSuchPaddingException
	            | InvalidKeyException e) {
	        e.printStackTrace();
	    }
	    return null;
	}
}
