package AES;

/**
 * 进制转换工具类
 * 
 * @author tanjierong
 *
 */
public class ParseSystemUtil {
	private static final char[] HEX_CHAR = {'0', '1', '2', '3', '4', '5', 
            '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};  
	
	public static String strTohex(String s) {
		String str = "";
		for (int i = 0;i<s.length();i++) {
			int ch =(int)s.charAt(i);
			String s4 = Integer.toString(ch);
			str = str+s4;
		}
		return str;
	}
	
	

	/**
     * 方法一：
     * byte[] to hex string
     * 
     * @param bytes
     * @return
     */
	public static String bytesToHexFun1(byte[] bytes) {
        // 一个byte为8位，可用两个十六进制位标识
        char[] buf = new char[bytes.length * 2];
        int a = 0;
        int index = 0;
        for(byte b : bytes) { // 使用除与取余进行转换
            if(b < 0) {
                a = 256 + b;
            } else {
                a = b;
            }

            buf[index++] = HEX_CHAR[a / 16];
            buf[index++] = HEX_CHAR[a % 16];
        }

        return new String(buf);
    }
	
	/**
     * 将16进制字符串转换为byte[]
     * 
     * @param str
     * @return
     */
	public static byte[] toBytes(String str) {
        if(str == null || str.trim().equals("")) {
            return new byte[0];
        }

        byte[] bytes = new byte[str.length() / 2];
        for(int i = 0; i < str.length() / 2; i++) {
            String subStr = str.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte) Integer.parseInt(subStr, 16);
        }

        return bytes;
    }
	
	 /**
     * 方法二：
     * byte[] to hex string
     * 
     * @param bytes
     * @return
     */
	public static String bytesToHexFun2(byte[] bytes) {
        char[] buf = new char[bytes.length * 2];
        int index = 0;
        for(byte b : bytes) { // 利用位运算进行转换，可以看作方法一的变种
            buf[index++] = HEX_CHAR[b >>> 4 & 0xf];
            buf[index++] = HEX_CHAR[b & 0xf];
        }

        return new String(buf);
    }
	
	/**
	 * 将二进制转换成16进制
	 * 
	 * @param buf
	 * @return
	 */
	public static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	/**
	 * 将16进制转换为二进制
	 * 
	 * @param hexStr
	 * @return
	 */
	public static byte[] parseHexStr2Byte(String hexStr) {
		int len = (hexStr.length())/2;
		byte[] result = new byte[len];
		byte high = 0;
		byte low = 0;
		for (int i = 0; i < len; i++) {
			high = (byte)((hexStr.indexOf(hexStr.charAt(2*i)))<<4);
			low = (byte)hexStr.indexOf(hexStr.charAt(2*i+1));
			result[i] = (byte) (high|low);
		}
		return result;
	}
}
