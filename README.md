# CryptographyProject

For this project, cryptography functionalitites have been implemented using the Bouncy Castle provider. Required libraries are:

bcpkix-jdk15to18-1.72

bcprov-jdk15to18-1.72

bcutil-jdk15to18-1.72

User interface is implemented using the JavaFX 17, and the Java SDK used is 17 as well.

This application assumes the existence of the  CA digital certificate, CRL list and a public key infrastructure.

For that reason, in the Main class, there are commented parts of the code which offer creating an empty CRL list and creating a new CA certificate which will have 1 year validity.
