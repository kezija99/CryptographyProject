package application;

import java.io.File;
import java.io.Serializable;

public class ChunkFile implements Serializable{
	
	byte[] signature = null;
	File path = null;
	
	public ChunkFile(File chunkFile, byte[] signature) {
		this.signature = signature;
		path = chunkFile;
	}
}

