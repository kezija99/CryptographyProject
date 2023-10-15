package application;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ButtonType;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.Alert.AlertType;
import javafx.stage.Stage;

public class LoginController {
	
	Parent root;
	Stage stage;
	Scene scene;
	
	@FXML
	TextField userName;
	@FXML
	TextField pass;
	@FXML
	Button loginButton;
	@FXML
	Label infoLabel;
	
	static String nick;
	static int counterTry = 0;
	String firstPass;
	static X509Certificate cer = null;
	
	public void login(ActionEvent event) throws Exception{
		String tmpNick = userName.getText();
		firstPass = pass.getText();
		String userPass = "";
		boolean flag = true;
		Path path = Paths.get(".\\CryptoProject\\Users.txt");
		List<String> lines = Files.readAllLines(path);
		int counter = 0;
		//Firstly it is checked if the entered username corresponds to the uploaded certificate's owner username
		if(nick.compareTo(tmpNick) != 0) {
			flag = false;
			counterTry++;
			infoLabel.setText("Username invalid!");
		}
		//Then it is checked if the validated username exists in the Users.txt. If it does, password is extracted and checked afterwards, 
		//incrementing the counter for every failed attempt.
		else {
			for(String line : lines) {
				String userNick = line.split(" ")[0];
				if(nick.compareTo(userNick) == 0) {
					userPass = line.split(" ")[1];
					break;
				}
				counter++;
			}
			if(counter == lines.size()) {
				counterTry++;
				flag = false;
				infoLabel.setText("Username does not exist!");
			}
		}
		//Password is being checked by creating an hash from the entered password using the same algorithm used in registration proccess,
		//and then the created hash is being compared to the extracted hash for the current user.
		if (flag) {
			LoggedViewController.input = nick;
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(firstPass.getBytes());
			byte[] digest = md.digest();
			StringBuffer hexString = new StringBuffer();
			for (int i = 0; i < digest.length; i++) {
		        hexString.append(Integer.toHexString(0xFF & digest[i]));
		    }
			//If the comparing is successful, the user is logged in
			if(userPass.compareTo(hexString.toString()) == 0) {
				FXMLLoader loader = new FXMLLoader(getClass().getResource("LoggedView.fxml"));
		        root = loader.load();
		        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		        scene = new Scene(root);
		        stage.setScene(scene);
		        stage.show();
		        stage.setOnCloseRequest(e -> {
		        	e.consume();
		        	try {
						logout(stage);
					} catch (Exception e1) {
						e1.printStackTrace();
					}
		        });
			}
			else {
				infoLabel.setText("Password invalid!");
				counterTry++;
			}
			//If the user failed to login 3 times, user's certificate is being revoked with a Certificate_hold reason
			if(counterTry == 3) {
				Main.crlList = addRevocationToCRL("SHA256withRSA", Main.crlList, cer);
				Main.writeCrlToFileBase64Encoded(Main.crlList);
				FXMLLoader loader = new FXMLLoader(getClass().getResource("RevocationView.fxml"));
		        root = loader.load();
		        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		        scene = new Scene(root);
		        stage.setScene(scene);
		        stage.show();
			}
		}
		else
			if(counterTry == 3) {
				Main.crlList = addRevocationToCRL("SHA256withRSA", Main.crlList, cer);
				Main.writeCrlToFileBase64Encoded(Main.crlList);
				FXMLLoader loader = new FXMLLoader(getClass().getResource("RevocationView.fxml"));
		        root = loader.load();
		        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		        scene = new Scene(root);
		        stage.setScene(scene);
		        stage.show();
			}
	}
	
	public X509CRL addRevocationToCRL(String sigAlg, X509CRL crl, X509Certificate certToRevoke) throws Exception{
		X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(crl);
		crlGen.setNextUpdate(Main.calculateDate(24 * 7));
		ExtensionsGenerator extGen = new ExtensionsGenerator();
		CRLReason crlReason = CRLReason.lookup(CRLReason.certificateHold);
		extGen.addExtension(Extension.reasonCode, false, crlReason);
		crlGen.addCRLEntry(certToRevoke.getSerialNumber(), new Date(), extGen.generate());
		
		ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(Main.caKeyPair.getPrivate());
		JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");

		return converter.getCRL(crlGen.build(signer));
	}
	
	public void logout(Stage stage) throws Exception{
		Alert alert = new Alert(AlertType.CONFIRMATION);
		alert.setTitle("Exit");
		alert.setHeaderText("You are about to exit the application!");
		alert.setContentText("Are you sure you want to exit?");
		
		if(alert.showAndWait().get() == ButtonType.OK){
			new File(".\\CryptoProject\\CurrentlyLoggedUser\\" + LoggedViewController.user.userName + "-private.key").delete();
			stage.close();
		}
	}
	
	public static byte[] serialize(Object obj) throws IOException {
	    try (ByteArrayOutputStream b = new ByteArrayOutputStream()) {
	        try (ObjectOutputStream o = new ObjectOutputStream(b)) {
	            o.writeObject(obj);
	        }
	        return b.toByteArray();
	    }
	}
}
