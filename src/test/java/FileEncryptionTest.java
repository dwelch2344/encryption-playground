import com.github.lemniscate.crypto.RsaUtil;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import static org.junit.Assert.assertTrue;

/**
 * Create some keys!
 *
  openssl genrsa -out private.pem 2048
  openssl pkcs8 -topk8 -in private.pem -outform DER -out private.der -nocrypt
  openssl rsa -in private.pem -pubout -outform DER -out public.der
 *
 */
public class FileEncryptionTest {

    private File idRsa;
    private RsaUtil util = new RsaUtil();

    @Before
    public void init(){
        String home = System.getProperty("user.home");
        idRsa = new File(home, "/.ssh/id_rsa");
        assertTrue(idRsa.exists());
    }

    @Test
    public void fromIdRsa() throws Exception {
        String data = util.loadStrippedDataFromFile(idRsa);
        RSAPrivateCrtKey priv = util.generatePrivateKey(data);
        RSAPublicKey pub = util.generatePublicKey(priv);

        String src = "Hello world";
        String encrypted = util.encrypt(src, pub);
        String decrypted = util.decrypt(encrypted, priv);
        assertTrue( src.equals(decrypted) );
    }

}
