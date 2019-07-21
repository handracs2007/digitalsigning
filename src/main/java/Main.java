import java.security.*;
import java.util.Base64;
import java.util.Optional;

public class Main {

    private static Optional < KeyPair > generateKeyPair ( String algorithm , int length ) {
        Optional < KeyPair > keyPair = Optional.empty ( );

        try {
            KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance ( algorithm );
            kpGenerator.initialize ( length );
            KeyPair kp = kpGenerator.generateKeyPair ( );

            keyPair = Optional.of ( kp );
        }
        catch ( NoSuchAlgorithmException e ) {
            e.printStackTrace ( );
        }

        return keyPair;
    }

    private static Optional < String > sign ( PrivateKey key , String toBeSigned , String algorithm ) {
        Optional < String > signature = Optional.empty ( );

        try {
            Signature signer = Signature.getInstance ( algorithm );
            signer.initSign ( key );
            signer.update ( toBeSigned.getBytes ( ) );

            byte[] signatureBytes = signer.sign ( );

            signature = Optional.of ( Base64.getEncoder ( ).encodeToString ( signatureBytes ) );
        }
        catch ( NoSuchAlgorithmException | InvalidKeyException | SignatureException e ) {
            e.printStackTrace ( );
        }

        return signature;
    }

    private static boolean verify ( PublicKey key , String signature , String plainText , String algorithm ) {
        try {
            Signature verifier = Signature.getInstance ( algorithm );
            verifier.initVerify ( key );
            verifier.update ( plainText.getBytes ( ) );

            return verifier.verify ( Base64.getDecoder ( ).decode ( signature.getBytes ( ) ) );
        }
        catch ( NoSuchAlgorithmException | InvalidKeyException | SignatureException e ) {
            e.printStackTrace ( );
        }

        return false;
    }

    public static void main ( String[] args ) {
        final String TO_BE_SIGNED = "Hello Digital Signing with Java";
        final String ALGORITHM = "RSA";
        final String SIGN_ALGORITHM = "SHA256withRSA";

        final int LENGTH = 2048;

        Optional < KeyPair > keyPair = generateKeyPair ( ALGORITHM , LENGTH );

        if ( keyPair.isPresent ( ) ) {
            Optional < String > signature = sign ( keyPair.get ( ).getPrivate ( ) , TO_BE_SIGNED , SIGN_ALGORITHM );

            if ( signature.isPresent ( ) ) {
                System.out.println ( "Signature: " + signature.get ( ) );

                System.out.println ( "Now verifying..." );

                boolean verified = verify ( keyPair.get ( ).getPublic ( ) , signature.get ( ) , TO_BE_SIGNED , SIGN_ALGORITHM );
                System.out.println ( "Result: " + verified );
            }
        }
    }
}
