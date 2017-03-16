package Protocol;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class SimpleProtocol implements Protocol {
	
	private static String escape(String str){
		str = str.replace("\\", "\\\\");
		str = str.replace("_", "\\_");
		str = str.replace("\n", "\\n");
		return str;
	}
	
	private static String unescape(String str){
		str = str.replace("\\\\", "\\");
		str = str.replace("\\_", "_");
		str = str.replace("\\n", "\n");
		return str;
	}
	
	public String createMessage(String... args){
		String result = "";
		for(String str: args){
			if(result!="") result = result + ":__:";
			result = result + escape(str);
		}
		System.out.println("send: " + result);
		return result;
	}
	
	public String[] decodeMessage(String str) {
		System.out.println("receive: " + str);
		if(str == null || str.equals("")){
			return new String[0];
		}
		String[] messages = str.split(":__:");
		for(int i=0; i<messages.length; i++){
			messages[i] = unescape(messages[i]);
		}
		if(messages.length == 1 && messages[0].equals("")){
			return new String[0];
		}
		return messages;
	}

}
