import junit.framework.Assert;
import org.junit.Test;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;

import static org.junit.Assert.*;

/**
 * Create some keys!
 *
  openssl genrsa -out private.pem 2048
  openssl pkcs8 -topk8 -in private.pem -outform DER -out private.der -nocrypt
  openssl rsa -in private.pem -pubout -outform DER -out public.der
 *
 */
public class FileEncryptionTest {

    @Test
    public void foo() throws Exception{
        FileEncryption secure = new FileEncryption();

        File encryptedKeyFile = file("private.pem");
        File publicKeyFile = file("public.der");
        File privateKeyFile = file("private.der");
        File fileToEncrypt = file("message.txt");

        File encryptedFile = new File("message.txt.enc");
        if( !encryptedFile.exists() ){
            encryptedFile.createNewFile();
        }

        System.out.println("Encrypting to " + encryptedFile);
        File decryptedFile = File.createTempFile("decrypted", ".txt");
        System.out.println("Decrypting to " + decryptedFile);


        // to encrypt a file
        secure.makeKey();
        secure.saveKey(encryptedKeyFile, publicKeyFile);
        secure.encrypt(fileToEncrypt, encryptedFile);

        // to decrypt it again
        secure.loadKey(encryptedKeyFile, privateKeyFile);
        secure.decrypt(encryptedFile, decryptedFile);
    }

    private File file(String path) throws URISyntaxException {
        URL url = getClass().getResource(path);
        assertNotNull("Could not load path " + path, url);
        File file = new File(url.toURI());
        assertNotNull("Could not create file " + path, file);
        return file;
    }
}
