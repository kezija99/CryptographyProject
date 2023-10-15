package application;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
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

public class RevocationController {
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
	Button registerButton;
	@FXML
	Label infoLabel;
	
	//After the revoked certificate is uploaded and login credentials are entered, it is firstly checked if the entered username corresponds
	//to the username of the uploaded certificate
	public void reactivate(ActionEvent event) throws Exception{
		String tmpNick = userName.getText();
		String firstPass = pass.getText();
		String userPass = "";
		boolean flag = true;
		Path path = Paths.get(".\\CryptoProject\\Users.txt");
		List<String> lines = Files.readAllLines(path);
		int counter = 0;
		if(LoginController.nick.compareTo(tmpNick) != 0) {
			flag = false;
			infoLabel.setText("Username invalid!");
		}
		else {
			//If the usernames are same, it is checked if the username exists in the Users.txt file
			for(String line : lines) {
				String userNick = line.split(" ")[0];
				if(LoginController.nick.compareTo(userNick) == 0) {
					userPass = line.split(" ")[1];
					break;
				}
				counter++;
			}
			if(counter == lines.size()) {
				flag = false;
				infoLabel.setText("Username does not exist!");
			}
		}
		if(flag) {
			LoggedViewController.input = LoginController.nick;
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(firstPass.getBytes());
			byte[] digest = md.digest();
			StringBuffer hexString = new StringBuffer();
			for (int i = 0; i < digest.length; i++) {
		        hexString.append(Integer.toHexString(0xFF & digest[i]));
		    }
			//If the login credentials are valid, certificate is being reactivated, and the user is logged in
			if(userPass.compareTo(hexString.toString()) == 0) {
				Main.crlList = reactivateCertificate("SHA256withRSA", Main.crlList, LoginController.cer);
				Main.writeCrlToFileBase64Encoded(Main.crlList);
				FXMLLoader loader = new FXMLLoader(getClass().getResource("LoggedView.fxml"));
		        root = loader.load();
		        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		        scene = new Scene(root);
		        stage.setScene(scene);
		        stage.show();
		        stage.setOnCloseRequest(e -> {
		        	e.consume();
		        	logout(stage);
		        });
			}
			else {
				infoLabel.setText("Password invalid!");
			}
		}
	}
	
	public void register(ActionEvent event) throws Exception{
		FXMLLoader loader = new FXMLLoader(getClass().getResource("RegisterScene.fxml"));
        root = loader.load();
        stage = (Stage)((Node)event.getSource()).getScene().getWindow();
        scene = new Scene(root);
        stage.setScene(scene);
        stage.show();
	}
	
	//Certificate reactivation is being done by creating a new empty crl list, extracting all crl entries from the current crl list and
	//adding all of the entries who's serial number differs from the target certificate to the new list.
	public X509CRL reactivateCertificate(String sigAlg, X509CRL crl, X509Certificate certToReactivate) throws Exception{
		X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(newEmptyCrl("SHA256withRSA"));
		crlGen.setNextUpdate(Main.calculateDate(24 * 7));
		ExtensionsGenerator extGen = new ExtensionsGenerator();
		CRLReason crlReason = CRLReason.lookup(CRLReason.certificateHold);
		extGen.addExtension(Extension.reasonCode, false, crlReason);
		Collection<? extends X509CRLEntry> set = crl.getRevokedCertificates();
		 
		for(X509CRLEntry entry : set) {
			if(!entry.getSerialNumber().equals(certToReactivate.getSerialNumber()))
				crlGen.addCRLEntry(entry.getSerialNumber(), entry.getRevocationDate(), extGen.generate());
		}	 
		ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(Main.caKeyPair.getPrivate());
		JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");

		return converter.getCRL(crlGen.build(signer));
	}
	
	public X509CRL newEmptyCrl(String sigAlg) throws Exception{
		CertificateFactory fac = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(new File(".\\CryptoProject\\CACertificate\\root-cert.crt"));
        X509Certificate caCert = (X509Certificate) fac.generateCertificate(is);
		X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(),Main.calculateDate(0));
		crlGen.setNextUpdate(Main.calculateDate(24 * 7));

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		crlGen.addExtension(Extension.authorityKeyIdentifier, false,
		extUtils.createAuthorityKeyIdentifier(caCert));

		ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(Main.caKeyPair.getPrivate());
		JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
		X509CRL list =  converter.getCRL(crlGen.build(signer));
		
		return list;
	}
	
	//Since the track of the currently logged user is being kept by writing the user's private key to the project folder, the same is 
	//being deleted after the logout is made
	public void logout(Stage stage) {
		Alert alert = new Alert(AlertType.CONFIRMATION);
		alert.setTitle("Exit");
		alert.setHeaderText("You are about to exit the application!");
		alert.setContentText("Are you sure you want to exit?");
		
		if(alert.showAndWait().get() == ButtonType.OK){
			new File(".\\CryptoProject\\CurrentlyLoggedUser\\" + LoggedViewController.user.userName + "-private.key").delete();
			stage.close();
		}
	}

}
