package application;

import java.io.File;
import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.cert.CRLReason;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class FirstSceneController {
	Stage stage;
	Scene scene;
	Parent root;
	
	@FXML
	Label label;
	@FXML
	Button login;
	
	public void switchToRegister(ActionEvent event) throws Exception{
		root = FXMLLoader.load(getClass().getResource("RegisterScene.fxml"));
		stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		scene = new Scene(root);
		stage.setScene(scene);
		stage.show();
	}
	
	//Method for uploading the user certificate and checking the certificate validity using the ca public key. If the certificate is not
	//valid, or it is expired, the exception is being throwed which is then caught and the proper message is displayed to the user.
	public void login(ActionEvent event) throws Exception{
		FileChooser fo = new FileChooser();
		fo.getExtensionFilters().add(new FileChooser.ExtensionFilter("Certs (.cer)", "*.crt"));
		File f = fo.showOpenDialog(null);
		if(f != null) {
			CertificateFactory fac = CertificateFactory.getInstance("X.509");
	        FileInputStream is = new FileInputStream(f);
	        X509Certificate cert = (X509Certificate) fac.generateCertificate(is);
	        try {
	        	cert.verify(Main.caKeyPair.getPublic());
	        	cert.checkValidity();
	        	X509CRLEntry tmp = Main.crlList.getRevokedCertificate(cert);
				//First it is checked if the certificate is not the root certificate
	        	if(cert.getSubjectX500Principal().getName().split("=")[1].compareTo("root-cert") == 0)
	        		label.setText("Uploaded certificate is not valid!");
				//Then it is checked if the certificate has been revoked. If it isn't, login gui is being displayed
	        	else if(tmp == null) {
		        	LoginController.nick = cert.getSubjectX500Principal().getName().split("=")[1];
		        	LoginController.cer = cert;
		        	root = FXMLLoader.load(getClass().getResource("LoginView.fxml"));
		    		stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		    		scene = new Scene(root);
		    		stage.setScene(scene);
		    		stage.show();
	        	}
	        	else	
	        		label.setText("Uploaded certificate is revoked!");
	        }
	        catch(Exception e) {
	        	label.setText("Uploaded certificate is not valid!");
	        }
		}
	}
	
	//Method which can reactivate the revoked user certificate. First it is checked wether the uploaded certificate has been signed by
	//proper ca certificate. If it is, it is extracted from the crl list if the revocation reason is Certificate_hold and it's username
	//is passed to the login controller so the user has the chance of reactivating it by entering correct credentials.
	public void reactivate(ActionEvent event) throws Exception{
		FileChooser fo = new FileChooser();
		fo.getExtensionFilters().add(new FileChooser.ExtensionFilter("Certs (.cer)", "*.crt"));
		File f = fo.showOpenDialog(null);
		if(f != null) {
			CertificateFactory fac = CertificateFactory.getInstance("X.509");
	        FileInputStream is = new FileInputStream(f);
	        X509Certificate cert = (X509Certificate) fac.generateCertificate(is);
	        try {
	        	cert.verify(Main.caKeyPair.getPublic());
	        	cert.checkValidity();
	        	X509CRLEntry tmp = Main.crlList.getRevokedCertificate(cert);
	        	if(tmp != null && (tmp.getRevocationReason() == CRLReason.CERTIFICATE_HOLD)){
	        		LoginController.nick = cert.getSubjectX500Principal().getName().split("=")[1];
		        	LoginController.cer = cert;
		        	root = FXMLLoader.load(getClass().getResource("RevocationView.fxml"));
		    		stage = (Stage)((Node)event.getSource()).getScene().getWindow();
		    		scene = new Scene(root);
		    		stage.setScene(scene);
		    		stage.show();
	        	}
	        	else
	        		label.setText("Uploaded certificate is not valid!");
	        }
	        catch(Exception e) {
	        	label.setText("Uploaded certificate is not valid!");
	        }
		}
	}
}
