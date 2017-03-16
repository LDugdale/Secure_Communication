package ChatClient;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import Protocol.KeyTool;
import Protocol.SimpleProtocol;

public class Client {
	
	private Socket clientSocket;			// socket connecting to server
	private DataOutputStream outToServer;	// output stream to server
	private BufferedReader inFromServer;	// input stream from server
	private SimpleProtocol protocol = new SimpleProtocol();		// pack and unpack messages
	public Integer offset = -1;		// offset of messages, at the beginning it is -1. Update it to the offset of the latest message
	private String host = "";		// IP address of server
	private Integer port = 0;		// Port number of server
	private Key key2;
	private Cipher cipher = null;
	
	public String createMessage(String... args){
		String result = protocol.createMessage(args);
		try {
			if(cipher == null){
				cipher = Cipher.getInstance("AES");
			}
			cipher.init(Cipher.ENCRYPT_MODE, key2);
			byte[] bytes = cipher.doFinal(result.getBytes());
			String string = Base64.getEncoder().encodeToString(bytes);
			return string;
			
		} catch (Exception e) {
			e.printStackTrace();
		} 
		return result;
	}
	
	/*
	 * 		Read a line from server and unpack it using SimpleProtocol
	 */
	public String[] getResponse(){
		try {
			byte[] bytes = Base64.getDecoder().decode(inFromServer.readLine());
			cipher.init(Cipher.DECRYPT_MODE, key2);
			byte[] bytes_raw = cipher.doFinal(bytes);
			return protocol.decodeMessage(new String(bytes_raw));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/*
	 * 		Send sign-up request to server, return the response to GuiSignUp
	 */
	public String[] signup(String user, String pass){
		String string = createMessage("sign-up", user, pass);
		try {
			outToServer.writeBytes(string + "\n");
			String[] response = this.getResponse();
			return response;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * 		Send sign-in request to server, return the response to GuiSignIn
	 */
	public String[] signin(String user, String pass){
		String string = createMessage("sign-in", user, pass);
		try {
			outToServer.writeBytes(string + "\n");
			String[] response = this.getResponse();
			if(response[1].equals("true")){
				System.out.println("Sign-in successful.");
			}else{
				System.out.println(response[2]);
			}
			return response;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}
	
	/*
	 * 		Send get-message request to server
	 */
	public void get_message(){
		String string = createMessage("get-message", this.offset.toString());
		try {
			outToServer.writeBytes(string + "\n");
		} catch (IOException e) {
			System.out.println("Unable to get message");
			e.printStackTrace();
		}
	}
	
	/*
	 * 		Send a message to server.
	 */
	public void send_message(String msg){
		String string = createMessage("send-message", msg);
		try {
			outToServer.writeBytes(string + "\n");
		} catch (IOException e) {
			System.out.println("Unable to send message.");
			e.printStackTrace();
		}
	}
	
	/*
	 * 		Initialize socket and input/output streams
	 */
	public void start(){
		try {
			clientSocket = new Socket(this.host, this.port);
			outToServer = new DataOutputStream(clientSocket.getOutputStream());
			inFromServer = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
			
			/***
			 *        RSA: key exchange
			 */
			
			// Create RSA cipher
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, KeyTool.getRSAPublicKey());
			
			// Create AES key1
			Key key1 = KeyTool.getAESKey();
			// Encrypt key1 with RSA
			byte[] key1RSA = cipher.doFinal(key1.getEncoded());
			// Transform byte[] to base64 string so that we can send it as a line
			String key1RSA_base64 = Base64.getEncoder().encodeToString(key1RSA);
			outToServer.writeBytes(key1RSA_base64 + "\n");
			
			// receive server's key2
			String key2str = inFromServer.readLine();
			// Transform from base64 string to byte[]
			byte[] key2_AES_with_key1 = Base64.getDecoder().decode(key2str);
			// Create cipher(AES, key1) to decode key2
			Cipher cipher_aes_key1 = Cipher.getInstance("AES");
			cipher_aes_key1.init(Cipher.DECRYPT_MODE, key1);
			// Decrypt key2
			byte[] key2bytes = cipher_aes_key1.doFinal(key2_AES_with_key1);
			key2 = new SecretKeySpec(key2bytes, "AES");
			
		} catch (UnknownHostException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	/*
	 * 		Close socket
	 */
	public void stop(){
		try {
			clientSocket.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void setHost(String host) {
		this.host = host;
	}

	public void setPort(Integer port) {
		this.port = port;
	}
	
}
