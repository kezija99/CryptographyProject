package application;

import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

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

public class RegistrationController {
	
	Parent root;
	Stage stage;
	Scene scene;
	
	@FXML
	Label label;
	@FXML
	TextField Username;
	@FXML
	TextField FirstPass;
	@FXML
	TextField SecondPass;
	@FXML
	Button Confirm;
	
	String userName;
	String firstPass;
	String secondPass;
	
	//Registration button which firstly checks if there is already an used with same username present in the file Users.txt. If there isn't
	//such user, entered password is being saved as an Hash using the SHA-256 hashing algorithm while the username is being saved as it is.
	public void confirm(ActionEvent event) throws Exception{
		Path path = Paths.get(".\\CryptoProject\\Users.txt");
		List<String> lines = Files.readAllLines(path);
		userName = Username.getText();
		firstPass = FirstPass.getText();
		secondPass = SecondPass.getText();
		boolean flag = true;
		int count = 0;
		for(int i = 0; i < lines.size(); i++) {
			String[] tmp = lines.get(i).split(" ");
			if(tmp[0].compareTo(userName) == 0) {
				count++;
				break;
			}
		}
		if(count != 0) {
			label.setText("Username already in use!");
			flag = false;
		}
		else 
			if(firstPass.compareTo(secondPass) != 0) {
				label.setText("Passwords do not match!");
				flag = false;
			}
		if(flag == true) {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(firstPass.getBytes());
			byte[] digest = md.digest();
			StringBuffer hexString = new StringBuffer();
			for (int i = 0; i<digest.length ;i++) {
		         hexString.append(Integer.toHexString(0xFF & digest[i]));
		    }
			Files.write(path, (userName + " " + hexString.toString() + "\n").getBytes(), StandardOpenOption.APPEND);
			//Next, an user certificate is being created using key pair generated using RSA algorithm with 2048 bytes length and signed
			//with the root ca certificate for the 6 months.
			Security.addProvider(new BouncyCastleProvider());
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
	        keyPairGenerator.initialize(2048);
	        KeyPair keys = keyPairGenerator.generateKeyPair();
	        X509Certificate userCert = generate(keys, "SHA256withRSA", userName, 183);
	        writeCertToFileBase64Encoded(userCert, ".\\CryptoProject\\UsersCertificates\\" + userName + "-cert.crt");
	        LoggedViewController.user = new User(keys, userName);
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
	}
	
	//Generating and returning the user certificate by using the passed keypair, SHA256withRSA algorithm, username and an certificate validity length
	//parameters. Certificate is being signed by the ca certificate preexisting in the project folder.
	public static X509Certificate generate(KeyPair keyPair, final String hashAlgorithm, final String cn,
            final int days) throws Exception {
			final Instant now = Instant.now();
			final Date notBefore = Date.from(now);
			final Date notAfter = Date.from(now.plus(Duration.ofDays(days)));
			
			final ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm).build(Main.caKeyPair.getPrivate());
			final X500Name x500NameIssuer = new X500Name("CN = root-cert");
			final X500Name x500Name = new X500Name("CN = " + cn);
			final X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(x500NameIssuer,
			BigInteger.valueOf(now.toEpochMilli()), notBefore, notAfter, x500Name, keyPair.getPublic())
			.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(keyPair.getPublic()))
			.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(Main.caKeyPair.getPublic()))
			.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
			.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
			
			return new JcaX509CertificateConverter()
			.setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
		}
	
	private static SubjectKeyIdentifier createSubjectKeyId(final PublicKey publicKey) throws OperatorCreationException {
	    final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
	    final DigestCalculator digCalc =
	      new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

	    return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
	  }
	
	private static AuthorityKeyIdentifier createAuthorityKeyId(final PublicKey publicKey)throws OperatorCreationException{
		final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
		final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

		return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
	}
	
	static void writeCertToFileBase64Encoded(Certificate certificate, String fileName) throws Exception {
	      FileOutputStream certificateOut = new FileOutputStream(fileName);
	      certificateOut.write("-----BEGIN CERTIFICATE-----\n".getBytes());
	      certificateOut.write(Base64.encode(certificate.getEncoded()));
	      certificateOut.write("-----END CERTIFICATE-----\n".getBytes());
	      certificateOut.close();
	  }
	
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
