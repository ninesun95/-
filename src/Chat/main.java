package chat;

public class main {
	public static void main(String[] arg) {
		
		MyServer server = new MyServer();
		MyClient client = new MyClient();

		new Thread(server).start();
		new Thread(client).start();

	}
}
