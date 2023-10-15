package application;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Alert;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class LoggedViewController implements Initializable{
	static User user;
	static String input;
	Stage stage;
	
	@FXML
	ListView<String> myListView;
	@FXML
	Button download;
	@FXML
	Button delete;
	@FXML
	Button uploadFile;
	@FXML
	Button compromise;
	@FXML
	Label label2;
	@FXML
	Label mainLabel;

	String currentFile;
	
	//Firstly, it is being checked wether the user is logged in for first time or not by checking the folder SerUsers inside the project
	//folder. By serializing the users, their state is being saved and extracted every time user logs in.
	public void initialize(URL arg0, ResourceBundle arg1) {
		try {
			File serFile = null;
			if(user != null)
				serFile = new File(".\\CryptoProject\\SerUsers\\" + user.userName + ".ser");
			else
				serFile = new File(".\\CryptoProject\\SerUsers\\" + input + ".ser");
			if(serFile.exists()) {
				FileInputStream fileIn = new FileInputStream(serFile);
		        ObjectInputStream in = new ObjectInputStream(fileIn);
		        user = (User) in.readObject();
		        in.close();
		        fileIn.close();
			}
			else {
		         FileOutputStream fileOut = new FileOutputStream(serFile);
		         ObjectOutputStream out = new ObjectOutputStream(fileOut);
		         out.writeObject(user);
		         out.close();
		         fileOut.close();
			}
	    } 
		catch (IOException | ClassNotFoundException i) {
	         i.printStackTrace();
	    }
		//After deserialization proccess, user's private key is being saved to the project folder. That is one of the ways of keeping track
		//on which user is currently logged in.
		try {
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(user.keys.getPrivate().getEncoded());
			FileOutputStream fos = new FileOutputStream(new File(".\\CryptoProject\\CurrentlyLoggedUser\\" + user.userName + "-private.key"));
			fos.write(pkcs8EncodedKeySpec.getEncoded());
			fos.close();
			}
			catch(Exception e) {
				e.printStackTrace();
			}
		//Displaying user info and it's list of files
		mainLabel.setText("Logged in as: " + user.userName);
		List<String> names = new ArrayList<>();
		for(int i = 0; i < user.userFiles.size(); i++)
			names.add(user.userFiles.get(i).DisplayName);
		
		myListView.getItems().addAll(names);
		
		myListView.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<String>() { 
			public void changed(ObservableValue<? extends String> arg0, String arg1, String arg2) {
				currentFile = myListView.getSelectionModel().getSelectedItem();
			}
		});
	}
	
	//Proccess of reasembling and decrypting of the choosen user file by checking if the file has been compromised in the same time and
	//alerting the user if so.
	public void download(ActionEvent event) throws Exception{
		label2.setText(" ");
		if(currentFile != null) {
			DirectoryChooser fc = new DirectoryChooser();
			File f = fc.showDialog(null);
			if(f != null) {
				for(int i = 0; i < user.userFiles.size(); i++) 
					if(currentFile.compareTo(user.userFiles.get(i).DisplayName) == 0) {
						if(user.userFiles.get(i).check(user.asKey, user.vec)) {
							Alert alert = new Alert(AlertType.CONFIRMATION);
							alert.setTitle("Warning");
							alert.setHeaderText("Your file has been compromised!");
							alert.setContentText("Are you sure you want to download it?");
							
							if(alert.showAndWait().get() == ButtonType.OK){
								user.userFiles.get(i).downloadFile(user.asKey, user.vec, f);
								break;
							}
						}
						else {
							user.userFiles.get(i).downloadFile(user.asKey, user.vec, f);
							break;
						}
					}	
			}
		}
	}
	
	//After deleteing the choosen user file, user object is being serialized so that updated user state is saved
	public void delete(ActionEvent event) throws Exception{
		label2.setText(" ");
		if(currentFile != null) 
			for(int i = 0; i < user.userFiles.size(); i++) {
				if(currentFile.compareTo(user.userFiles.get(i).DisplayName) == 0) {
					user.delete(user.userFiles.get(i));
					myListView.getItems().remove(currentFile);
					try {
				         FileOutputStream fileOut = new FileOutputStream(".\\CryptoProject\\SerUsers\\" + user.userName + ".ser");
				         ObjectOutputStream out = new ObjectOutputStream(fileOut);
				         out.writeObject(user);
				         out.close();
				         fileOut.close();
				    } 
					catch (IOException ex) {
				         ex.printStackTrace();
				    }
					break;
				}
			}
	}
	
	//Method which compromises the user file integrity by changing it's content
	public void compromise(ActionEvent event) throws Exception{
		label2.setText(" ");
		if(currentFile != null) {
			for(int i = 0; i < user.userFiles.size(); i++) 
				if(currentFile.compareTo(user.userFiles.get(i).DisplayName) == 0) {
					KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
					keyPairGen.initialize(2048);
					KeyPair pair = keyPairGen.generateKeyPair();
					EncryptedFile tmp = user.userFiles.get(i);
					int index = Main.rand.nextInt(tmp.chunkFiles.size() - 1);
					//After file to compromise is picked, random chunk file is choosen
					ChunkFile chunkTmp = tmp.chunkFiles.get(index);
					Signature sign = Signature.getInstance("SHA256withRSA");
					sign.initSign(pair.getPrivate());
					IvParameterSpec ivParameterSpec = new IvParameterSpec(user.vec);
					Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
					cipher.init(Cipher.ENCRYPT_MODE, user.asKey, ivParameterSpec);
					//On the file path of the choosen chunk file, a new chunk file is being written and its signature made by using the //same algorithm is being saved. This chunk file has different content and therefore its signature will differ
					FileOutputStream out = new FileOutputStream(chunkTmp.path);
					byte[] bytes = "Compromise chunk".getBytes();
					byte[] ciphered = cipher.doFinal(bytes);
					out.write(ciphered);
					out.close();
					sign.update(bytes);
					byte[] signature = sign.sign();
					chunkTmp.signature = signature;
					break;
				}
			label2.setText("Done");
		}
	}
	
	//Serializing the user after uploading the new file successfuly so its new state is being saved
	public void upload(ActionEvent event) throws Exception{
		FileChooser fc = new FileChooser();
		File f = fc.showOpenDialog(null);
		if (f != null) {
			user.userFiles.add(new EncryptedFile(f, user.keys, user.asKey, user.vec));
			myListView.getItems().add(f.getName());
			try {
		         FileOutputStream fileOut = new FileOutputStream(".\\CryptoProject\\SerUsers\\" + user.userName + ".ser");
		         ObjectOutputStream out = new ObjectOutputStream(fileOut);
		         out.writeObject(user);
		         out.close();
		         fileOut.close();
		    } 
			catch (IOException i) {
		         i.printStackTrace();
		    }
		}
	}	
}
