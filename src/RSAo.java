/**
 *
 * @author breza
 */
import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
 
public class RSAo
{
    private BigInteger P;
    private BigInteger Q;
    private BigInteger N;
    private BigInteger PHI;
    private BigInteger e;

    public BigInteger getP() {
        return P;
    }
    public BigInteger getQ() {
        return Q;
    }

    public BigInteger getPHI() {
        return PHI;
    }
    public BigInteger getN() {
        return N;
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getD() {
        return d;
    }
    private BigInteger d;
    private int maxLength = 1024; //1024
    private Random R;
 
    public RSAo()
    {
        R = new Random();
        P = BigInteger.probablePrime(maxLength, R);
        Q = BigInteger.probablePrime(maxLength, R);
        N = P.multiply(Q);
       PHI = P.subtract(BigInteger.ONE).multiply(  Q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(maxLength / 2, R);
        while (PHI.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(PHI) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(PHI);
    }
    public RSAo(String p, String q) // I used this generator function for small primes
    {
        R = new Random();   
        P = new BigInteger(p);
        Q = new BigInteger(q);
        N = P.multiply(Q);
       PHI = P.subtract(BigInteger.ONE).multiply(  Q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(maxLength / 2, R);
        while (PHI.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(PHI) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(PHI);
    }
 
    public static void main (String [] arguments) throws IOException
    {
        /**RSAo rsa = new RSAo();
        DataInputStream input = new DataInputStream(System.in);
        String inputString;
        System.out.println("Enter message you wish to send.");
        inputString = input.readLine();
        System.out.println("Encrypting the message: " + inputString);
        System.out.println("The message in bytes is:: "
                + bToS(inputString.getBytes()));
        // encryption
        byte[] cipher = rsa.encryptMessage(inputString.getBytes());
        // decryption
        byte[] plain = rsa.decryptMessage(cipher);
        System.out.println("Decrypting Bytes: " + bToS(plain));
        System.out.println("Plain message is: " + new String(plain));**/
    }
 
    private static String bToS(byte[] cipher)
    {
        String temp = "";
        for (byte b : cipher)
        {
            temp += Byte.toString(b);
        }
        return temp;
    }
    /*private static byte[] sToB(String cipher){
        byte[] result = null;
        for (int i = 0; i < cipher.length()/2; i+=2) {
            
        }
        return result;
    }*/
    // Encrypting the message
    public byte[] encryptMessage(String x)
    {
        byte[] message = x.getBytes();
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }
    public BigInteger encryptMessage(String message, String eN){
        byte[] m = message.getBytes();
        String[] part = eN.split("N");
        BigInteger e = new BigInteger(part[0]);
        BigInteger N = new BigInteger(part[1]);
        return new BigInteger(m).modPow(e, N);
    }
 
    // Decrypting the message
    public byte[] decryptMessage(byte[] message)
    {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }
    public BigInteger decryptMessage(String code, String dN){
        //don't know
        String[] part = dN.split("N");
        BigInteger d = new BigInteger(part[0]);
        BigInteger N = new BigInteger(part[1]);
        return (new BigInteger(code)).modPow(d, N);
    }
}
