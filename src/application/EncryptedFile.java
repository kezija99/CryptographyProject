package application;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

//Since the idea of the "Safe repository application" is in reasembling the file into the chunks and saving them encrypted, every encrypted
//file object holds the list of it's chunk files next to the key pair and it's display name
public class EncryptedFile implements Serializable{

	PrivateKey privKey = null;
	PublicKey pubKey = null;
	ArrayList<ChunkFile> chunkFiles = new ArrayList<>();
	String DisplayName = null;
	
	//In the constructor itself, method which does all of the dissasembling and encrypting logic is being called
	public EncryptedFile(File f, KeyPair keys, SecretKey key, byte[] vec) throws Exception{
		DisplayName = f.getName();
		this.privKey = keys.getPrivate();
		this.pubKey = keys.getPublic();
		uploadFile(f, key, vec);
	}
	
	//Every file is divided into the range of [4, 1004] chunks 
	void uploadFile(File f, SecretKey asKey, byte[] vec) throws Exception{
		Signature sign = Signature.getInstance("SHA256withRSA");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(vec);
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		int numberOfChunks = Main.rand.nextInt(1000) + 4;
		int maxChunkSize = getSizeInBytes(f.length(), numberOfChunks);
		sign.initSign(privKey);
		File[] files = Main.directory.listFiles();
		ArrayList<File> fileList = new ArrayList<>();
		for(File tmp : files) {
			if(tmp.isDirectory())
				fileList.add(tmp);
		}
		int counter = 0;
		cipher.init(Cipher.ENCRYPT_MODE, asKey, ivParameterSpec);
		//For improved security, every chunk is being saved in the different subfolder of the targed folder. If there is no more available
		//subfolders, new will be created with a random generated name
		try (InputStream in = Files.newInputStream(f.toPath())) {
			byte[] buffer = new byte[maxChunkSize];
			int dataRead = in.read(buffer);
			while(dataRead > -1) {
				sign.update(buffer, 0, dataRead);
				byte[] signature = sign.sign();
				//For every chunk, signature is being made and saved as the chunk object field next to its path field
				if(counter <= fileList.size() - 1) {
					byte[] tmp = cipher.doFinal(buffer, 0, dataRead);
					File fileChunk = stageFile(tmp, tmp.length, fileList.get(counter));
					chunkFiles.add(new ChunkFile(fileChunk, signature));
					dataRead = in.read(buffer);
					counter++;
				}
				else {
					File newDir = new File(Main.directory + File.separator + Main.rand.nextInt());
					newDir.mkdir();
					byte[] tmp = cipher.doFinal(buffer, 0, dataRead);
					File fileChunk = stageFile(tmp, tmp.length, newDir);
					chunkFiles.add(new ChunkFile(fileChunk, signature));
					dataRead = in.read(buffer);
				}
			}
		}
	}
	
	//To reasemble the original file, it is needed to iterate trough all of it's chunks, decrypt each chunk using the same algorythim and
	//key, verify it's integrity and append them to the opened outputstream
	public void downloadFile(SecretKey asKey , byte[] vec, File f) throws Exception{
		Signature sign = Signature.getInstance("SHA256withRSA");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(vec);
		boolean flag = false;
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		sign.initVerify(pubKey);
		c.init(Cipher.DECRYPT_MODE, asKey, ivParameterSpec);
		File outputFile = new File(f + "\\" + DisplayName);
		FileOutputStream fos = new FileOutputStream(outputFile, true);
		for (int i = 0; i < chunkFiles.size(); i++) {
			File file = chunkFiles.get(i).path;
			InputStream in = Files.newInputStream(file.toPath());
			byte[] tmp = in.readAllBytes();
			try {
				byte[] decipher = c.doFinal(tmp);
				sign.update(decipher);
				if(!sign.verify(chunkFiles.get(i).signature))
					flag = true;
				
				fos.write(decipher);
			}
			catch(IllegalBlockSizeException e) {
				e.printStackTrace();
			}
		}
		fos.close();
	}
	
	//File integrity is being checked by iterating trough all of it's chunks and verifying its content
	public boolean check(SecretKey asKey, byte[] vec) throws Exception{
		Signature sign = Signature.getInstance("SHA256withRSA");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(vec);
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5PADDING");
		boolean flag = false;
		sign.initVerify(pubKey);
		c.init(Cipher.DECRYPT_MODE, asKey, ivParameterSpec);
		for (int i = 0; i < chunkFiles.size(); i++) {
			File file = chunkFiles.get(i).path;
			InputStream in = Files.newInputStream(file.toPath());
			byte[] tmp = in.readAllBytes();
			try {
				byte[] decipher = c.doFinal(tmp);
				sign.update(decipher);
				if(!sign.verify(chunkFiles.get(i).signature))
					flag = true;
			}
			catch(IllegalBlockSizeException e) {
				e.printStackTrace();
			}
		}
		return flag;
	}
	
	private int getSizeInBytes(long totalBytes, int numberOfFiles) {
		if (totalBytes % numberOfFiles != 0) {
	        totalBytes = ((totalBytes / numberOfFiles) + 1)*numberOfFiles;
	    }
	    long x = totalBytes / numberOfFiles;
	    return (int) x;
	}
	
	private File stageFile(byte[] buffer, int length, File f) throws Exception{
		File outputFile = File.createTempFile("temp-", "-split", f);
		try(FileOutputStream fos = new FileOutputStream(outputFile)){
			fos.write(buffer, 0, length);
		}
		return outputFile;
	}
}