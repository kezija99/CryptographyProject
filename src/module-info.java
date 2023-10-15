module Kripto {
	requires javafx.controls;
	requires javafx.fxml;
	requires javafx.graphics;
	requires javafx.base;
	requires org.bouncycastle.pkix;
	requires org.bouncycastle.provider;
	
	opens application to javafx.graphics, javafx.fxml;
}
