package application;

import java.io.Serializable;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.ArrayList;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class User implements Serializable{
	
	KeyPair keys = null;
	String userName = null;
	byte[] vec = null;
	ArrayList<EncryptedFile> userFiles = new ArrayList<>();
	SecretKey asKey = null;;
	
	public User(KeyPair keys, String userName) throws Exception{
		
		this.userName = userName;
		SecureRandom secure = new SecureRandom();
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(128, secure);
		asKey = keygen.generateKey();
		this.keys = keys;
		vec = createInitializationVector();;
	}
	
	void delete(EncryptedFile fileToDelete) {
		for(int i = 0; i < fileToDelete.chunkFiles.size(); i++) {
			fileToDelete.chunkFiles.get(i).path.delete();
		}
		userFiles.remove(fileToDelete);
	}
	
	public byte[] createInitializationVector(){
        byte[] initializationVector = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);
        return initializationVector;
    }
}