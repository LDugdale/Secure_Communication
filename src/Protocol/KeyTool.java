package Protocol;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.KeyGenerator;

public class KeyTool {
	
	private static boolean _INIT_ = false;
	private static Key RSA_private = null;
	private static Key RSA_public = null;
	private static Key AESKey = null;
	
	private static void init(){
		if(_INIT_ == true){
			return;
		}
		try {
			// Create RSA keys
			BigInteger m_pub = new BigInteger("102387507311734205623866723743820563846882218789546679129124190900346431077879949248369985722651346987005379841969713115665502738665749075656610325267727220708268342062579542486210389653678696926563337228554397781540962029289294845571824292853611290570148777923535178702581523559792112617183279531828910116471");
			BigInteger e_pub = new BigInteger("65537");
			BigInteger m_priv = new BigInteger("102387507311734205623866723743820563846882218789546679129124190900346431077879949248369985722651346987005379841969713115665502738665749075656610325267727220708268342062579542486210389653678696926563337228554397781540962029289294845571824292853611290570148777923535178702581523559792112617183279531828910116471");
			BigInteger e_priv = new BigInteger("36230963914528098060989871223018183563071937011892168327563347592503991380855301631428785859804498038903852234846264199847394204989508015526381281616245197276558589565270185696236328433288091021896441591928250645409910768042736562483933979979101401484327438022293555735717590681291713821728696013489686785073");
			RSAPublicKeySpec keySpec_pub = new RSAPublicKeySpec(m_pub, e_pub);
			RSAPrivateKeySpec keySpec_priv = new RSAPrivateKeySpec(m_priv, e_priv);
		    KeyFactory fact = KeyFactory.getInstance("RSA");
		    RSA_public = fact.generatePublic(keySpec_pub);
			RSA_private = fact.generatePrivate(keySpec_priv);
			
			// Create AES key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		    keyGenerator.init(128); // 128 default; 192 and 256 also possible
		    AESKey = keyGenerator.generateKey();
			_INIT_ = true;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static Key getRSAPrivateKey(){
		init();
		return RSA_private;
	}
	
	public static Key getRSAPublicKey(){
		init();
		return RSA_public;
	}
	
	
	
	public static Key getAESKey(){
		init();
		return AESKey;
	}
}
