package chat;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.UnknownHostException;

import java.util.Calendar;
import java.util.Map;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import AES.*;
import RSA.*;
import java.security.InvalidAlgorithmParameterException;

/**
 * 简单聊天软件的客户端
 */
public class MyClient extends JFrame implements Runnable, ActionListener {

	JTextArea jTextArea = null;
	JTextField jTextField = null;
	JPanel jPanel1 = null;
	JPanel jPanel2 = null;
	JScrollPane jScrollPane = null;
	JButton sendButton = null;
	JButton sendfButton = null;
	PrintWriter printWriter = null;
         String rec_publicK;
	String password;
	String publicKey;
	String privateKey;
	/**
	 * 客户端的主函数
	 */
	// public static void main(String[] args) {
	// // TODO Auto-generated method stub
	// new MyClient();
	// }

	/**
	 * 客户端构造函数用来初始化
	 */
	public MyClient() {
		// GUI初始化
		jTextArea = new JTextArea();
		jTextField = new JTextField(20);
		sendButton = new JButton("发送");
		sendfButton = new JButton("发送文件");
		sendButton.addActionListener(this);
		sendfButton.addActionListener(this);
		sendButton.setActionCommand("send");
		sendfButton.setActionCommand("sendf");
		jScrollPane = new JScrollPane(jTextArea);

		jPanel1 = new JPanel();
		jPanel1.add(jTextField, BorderLayout.CENTER);
		jPanel1.add(sendButton);
		jPanel1.add(sendfButton);

		this.add(jScrollPane, BorderLayout.CENTER);
		this.add(jPanel1, BorderLayout.SOUTH);

		this.setSize(600, 300);
		this.setTitle("聊天客户端");
		this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		this.setVisible(true);
		this.setResizable(true);
               //1、生成密钥对
		Map<String, String> keyMap = RSAUtils.createKeys(1024);
		publicKey = keyMap.get("publicKey");
		privateKey = keyMap.get("privateKey");

	}

	/**
	 * 用来获取当前的时间
	 * 
	 * @return 当前的时间
	 */
	public String getTime() {
		// 可以对每个单独时间域进行修改
		Calendar c = Calendar.getInstance();
		int hour = c.get(Calendar.HOUR_OF_DAY);// 获取小时
		int minute = c.get(Calendar.MINUTE);
		int second = c.get(Calendar.SECOND);
		return hour + ":" + minute + ":" + second;
	}

	/**
	 * 当button被点击的时候调用
	 */
	@Override
	public void actionPerformed(ActionEvent e) {
		// TODO Auto-generated method stub
            try{
		if (e.getActionCommand().equals("send")) {
			String info = jTextField.getText();
			// 将客户端发送的信息发送给服务端

			// System.out.println(password);
			byte[] encrypt = AES.encrypt(info, password);
			// System.out.println(encrypt);
			String hexStrResult = ParseSystemUtil.bytesToHexFun1(encrypt);
			// System.out.println(hexStrResult);
                         String sign = RSAUtils.sign(hexStrResult, RSAUtils.getPrivateKey(privateKey));
                         System.out.println("客户端产生的签名是:"+hexStrResult);
			String digest = MD5.MD5.getMD5(info.getBytes());
			// System.out.println(digest);

			String string = hexStrResult + "," + digest+","+sign;
			// System.out.println(string);

			jTextArea.append("客户端 " + getTime() + "\r\n" + info + "\r\n");
			printWriter.println(string);
			jTextField.setText("");
		} else if (e.getActionCommand().equals("sendf")) {
			printWriter.println("传输文件");

		}}
            catch(InvalidAlgorithmParameterException ex){
                 ex.printStackTrace();
            }
            catch(Exception ex){
                    ex.printStackTrace();
                }
	}

	public void run() {
		// socket通信代码
		try {
			Socket s = new Socket("127.0.0.1", 3030);
			BufferedReader br = new BufferedReader(new InputStreamReader(s.getInputStream()));
			printWriter = new PrintWriter(s.getOutputStream(), true);
			System.out.println("客户端生成的公钥："+publicKey);
			System.out.println("客户端生成的私钥："+privateKey);
                        //2、将公钥发送给服务器端
			printWriter.println(publicKey);
                        //客户端收到服务器端用公钥加密后的密钥                        
			String encode = br.readLine();
			String decodedData = RSAUtils.privateDecrypt(encode, RSAUtils.getPrivateKey(privateKey));
			password = decodedData;
			System.out.println("密钥种子："+decodedData);
                       rec_publicK = br.readLine();
                        System.out.println("客户端收到服务端公钥:"+rec_publicK);
                        /*String sign = RSAUtils.sign("hello",RSAUtils.getPrivateKey(privateKey));
                       printWriter.println(sign);*/
			while (true) {
				// 不停的读取服务器发过来的信息
				String info = br.readLine();

				String a[] = info.split(",");
				String info2 = new String(a[0]);
				String digest = new String(a[1]);
                                String rec_sign = new String(a[2]);
				System.out.println("收到的加密信息"+info2);
				System.out.println("收到的摘要"+digest);
                               boolean flag = RSAUtils.verify(info2, rec_sign, RSAUtils.getPublicKey(rec_publicK));
                               if(!flag) JOptionPane.showMessageDialog(null, "数字签名不正确", "alert", JOptionPane.ERROR_MESSAGE);
				byte[] info3 = ParseSystemUtil.toBytes(info2);
				byte[] decrypt = AES.decrypt(info3, decodedData);

				String digest2 = MD5.MD5.getMD5(decrypt);
				System.out.println("解密消息后哈希结果"+digest2);

				if (digest.equals(digest2)) {
					jTextArea.append("服务端 " + getTime() + "\r\n" + new String(decrypt) + "\r\n");
				} else {
					JOptionPane.showMessageDialog(null, "消息不完整", "alert", JOptionPane.ERROR_MESSAGE);
				}
			}
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}