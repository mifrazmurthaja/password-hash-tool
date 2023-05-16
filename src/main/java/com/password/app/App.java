package com.password.app;

import org.apache.axiom.om.util.Base64;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class App {
    static String digestFunction = "SHA-256";

    public static void main(String[] args) {
        char[] password;
        String salt;

        java.io.Console console = System.console();

        System.out.print("Enter the Password: ");
        password = console.readPassword();

        System.out.print("Enter the Salt Value: ");
        salt = console.readLine();

        System.out.println("Hash Value of the given password and the salt: " + preparePassword(password, salt));
    }

    public static String preparePassword(Object password, String saltValue) {

        Secret credentialObj = null;
        try {
            credentialObj = Secret.getSecret(password);
        } catch (UnsupportedSecretTypeException e) {
            String msg = "Unsupported secret type.";
            throw new RuntimeException(msg, e);
        }

        try {
            String passwordString;
            if (saltValue != null) {
                credentialObj.addChars(saltValue.toCharArray());
            }

            MessageDigest digest = MessageDigest.getInstance(digestFunction);
            byte[] byteValue = digest.digest(credentialObj.getBytes());
            passwordString = Base64.encode(byteValue);

            return passwordString;
        } catch (NoSuchAlgorithmException e) {
            String msg = "Error occurred while preparing password.";
            throw new RuntimeException(msg, e);
        } finally {
            credentialObj.clear();
        }
    }
}
