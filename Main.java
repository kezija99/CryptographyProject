package application;
	
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.stage.Stage;
import javafx.scene.Parent;
import javafx.scene.Scene;

public class Main extends Application {
	static KeyPair caKeyPair = null;
	static File directory = new File(".\\CryptoProject\\Repository");
	static Random rand = new Random();
	static X509CRL crlList = null;
	 
	public void start(Stage stage) {
		try {
			Parent root = FXMLLoader.load(getClass().getResource("FirstScene.fxml"));
			Scene scene = new Scene(root);
			stage.setScene(scene);
			stage.show();
		} catch(Exception e) {
			e.printStackTrace();
		}
	} 
	
	//Inititalizing the application by opening input streams to the preexisting root certificate and the crl list in project folder and getting
	//the reference to the crl list as well as the root certificate key pair
	public static void main(String[] args) throws Exception{
		
		Security.addProvider(new BouncyCastleProvider());
		CertificateFactory fac = CertificateFactory.getInstance("X.509");
		FileInputStream rootCertStream = new FileInputStream(".\\CryptoProject\\CACertificate\\root-cert.pfx");
		FileInputStream crlListStream = new FileInputStream(new File(".\\CryptoProject\\CRLList\\list.crl"));
		crlList = (X509CRL) fac.generateCRL(crlListStream);
	    KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
	    keystore.load(rootCertStream, "pass".toCharArray());

	    String alias = "root-cert";
	    Key key = keystore.getKey(alias, "pass".toCharArray());
	    if (key instanceof PrivateKey) {
	      Certificate cert = keystore.getCertificate(alias);
	      PublicKey publicKey = cert.getPublicKey();
	      caKeyPair = new KeyPair(publicKey, (PrivateKey) key);
	      //createEmptyCRL("SHA256withRSA");
	    }
	    
	    //If a new CA certificate is needed to be created
	    /*X509Certificate userCert = RegistrationController.generate(caKeyPair, "SHA256withRSA", "root-cert", 365);
	    RegistrationController.writeCertToFileBase64Encoded(userCert, ".\\CryptoProject\\CACertificate\\" + "root" + "-cert.crt");*/
		launch(args);
	}
	
	//Method for creating an empty CRL list used in case when it is needed it's reset. List is made from the key pair read from the ca certificate
	//which is preexisting on the project folder. Everything was done using the Bouncy Castle provider.
	public static void createEmptyCRL(String sigAlg) throws Exception{
		CertificateFactory fac = CertificateFactory.getInstance("X.509");
        FileInputStream is = new FileInputStream(new File(".\\CryptoProject\\CACertificate\\root-cert.crt"));
        X509Certificate caCert = (X509Certificate) fac.generateCertificate(is);
        X509v2CRLBuilder crlGen = new JcaX509v2CRLBuilder(caCert.getSubjectX500Principal(),calculateDate(0));
		crlGen.setNextUpdate(calculateDate(24 * 7));
		
		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		crlGen.addExtension(Extension.authorityKeyIdentifier, false,
		extUtils.createAuthorityKeyIdentifier(caCert));
		
		ContentSigner signer = new JcaContentSignerBuilder(sigAlg).setProvider("BC").build(caKeyPair.getPrivate());
		JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider("BC");
		X509CRL list =  converter.getCRL(crlGen.build(signer));
		
		writeCrlToFileBase64Encoded(list);
	}
	
	public static Date calculateDate(int hoursInFuture){
	  long secs = System.currentTimeMillis() / 1000;
	  return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
	}
	
	static void writeCrlToFileBase64Encoded(X509CRL crl) throws Exception {
	      FileOutputStream certificateOut = new FileOutputStream(new File(".\\CryptoProject\\CRLList\\list.crl"));
	      certificateOut.write("-----BEGIN X509 CRL-----\n".getBytes());
	      certificateOut.write(Base64.encode(crl.getEncoded()));
	      certificateOut.write("-----END X509 CRL-----\n".getBytes());
	      certificateOut.close();
	  }
}
