package ChatServer;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import Protocol.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

public class Handler implements Runnable{
	
	private Socket socket = null;
	private Protocol protocol = new SimpleProtocol();
	private BufferedReader in;
	private DataOutputStream out;
	private Server server;
	private String username;
	private Key key2;
	Cipher serverCipher = null;
	
	public Handler(Socket socket) {
		this.socket = socket;
	}
	
	public void sendToClient(String... args){

		String result = protocol.createMessage(args);
		try {

			if(serverCipher == null){

				serverCipher = Cipher.getInstance("AES");
			}

			serverCipher.init(Cipher.ENCRYPT_MODE, key2);
			byte[] bytes = serverCipher.doFinal(result.getBytes());
			String string = Base64.getEncoder().encodeToString(bytes);
			out.writeBytes(string + "\n");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public String[] getFromClient() throws Exception {

		if(serverCipher == null){

			serverCipher = Cipher.getInstance("AES");
		}

		byte[] bytes = Base64.getDecoder().decode(in.readLine());
		serverCipher.init(Cipher.DECRYPT_MODE, key2);
		byte[] bytes_raw = serverCipher.doFinal(bytes);
		return protocol.decodeMessage(new String(bytes_raw));

	}

	@Override
	public void run() {
		try {
			in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			out = new DataOutputStream(socket.getOutputStream());
			server = Server.getInstance();
			
			// Key exchange

			// receive clients's key1
			String key1str = in.readLine();
			// Transform from base64 string to byte[]
			byte[] Key1byes = Base64.getDecoder().decode(key1str);
			// create RSA Cipher
			Cipher RSAcipher = Cipher.getInstance("RSA");
			// Initialise the cipher
			RSAcipher.init(Cipher.DECRYPT_MODE, KeyTool.getRSAPrivateKey());
			byte[] result = RSAcipher.doFinal(Key1byes);
			// save the received key1
			Key key1 = new SecretKeySpec(result, "AES");


			// Create RSA cipher
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, KeyTool.getRSAPrivateKey());
			// send private key
			key2 = KeyTool.getAESKey();
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, key1);
			byte[] bytes = cipher.doFinal(key2.getEncoded());
			String string = Base64.getEncoder().encodeToString(bytes);
			out.writeBytes(string + "\n");

			// Sign in or create account
			String[] message = getFromClient();

			switch(message[0]){
				case "sign-in":{
						if(server.users.containsKey(message[1])){
							if(server.users.get(message[1]).equals(message[2])){
								this.username = message[1];
								sendToClient("sign-in", "true", "welcome");
							}else{
								sendToClient("sign-in", "false", "Username and password do not match");
								return;
							}
						}else{
							sendToClient("sign-in", "false", "Username does not exist");
							return;
						}
						break;
					}
				case "sign-up":{
					if(false == server.users.containsKey(message[1])){
						server.users.put(message[1], message[2]);
						sendToClient("sign-up","true","Registration successfully!");
					}else{
						sendToClient("sign-up", "false", "Username exists.");
					}
					return;
				}
				default: return;
			}
			SimpleDateFormat dFormat = new SimpleDateFormat("hh:mm");
			while(true){
				message = getFromClient();
				switch(message[0]){
					case "send-message":{
							server.messages.add(new Message(username, new Date(), message[1]));
							sendToClient("send-message","true","ok!");
							break;
						}
					case "get-message":{
							int offset = Integer.parseInt(message[1]);
							if(offset < -1) offset = -1;
							ArrayList<String> newMessages = new ArrayList<>();
							newMessages.add("get-message");
							for(int i=offset+1; i<server.messages.size();i++){
								newMessages.add(Integer.toString(i));
								newMessages.add(server.messages.get(i).getUsername());
								newMessages.add(dFormat.format(server.messages.get(i).getTimestamp()));
								newMessages.add(server.messages.get(i).getContent());
							}
							if(newMessages.size() < 1){
								out.writeBytes("\n");
							}
							sendToClient(newMessages.toArray(new String[newMessages.size()]));
							break;
						}
					default: return;
				}
			}
			
			

		} catch (Exception e) {
			try {
				socket.close();
				e.printStackTrace();
				return;
			} catch (IOException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
		}
	}
	
}
