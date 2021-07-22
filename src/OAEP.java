
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Optimal Asymmetric Encryption Padding
 * @author breza
 */
public class OAEP {
    private int r = new Random().nextInt();
    private int k0;
    private int k1;
    
    public static String bytesToHex(byte[] bytes) {
        byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes();
        byte[] hexChars = new byte[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] hexToBytes(String hex){
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for(int i = 0; i<hex.length();i+=2){
            outputStream.write((byte)Integer.parseInt(String.valueOf(hex.charAt(i))
                    +String.valueOf(hex.charAt(i+1)), 16));
        }
        return outputStream.toByteArray();
    }
    public String hash(String input, String algorithm){
        String hash = "";
        byte[] byteInput = input.getBytes();
        try{
            MessageDigest mD = MessageDigest.getInstance(algorithm);
            mD.update(byteInput);
            byte[] digest = mD.digest(); //not right?
            hash = bytesToHex(digest);
        }
        catch(Exception e){
            return e.toString();
        }
        return hash;
    }
        public static byte[] MGF1(byte[] seed, int seedOffset, int seedLength, int desiredLength){
        int hLen = 32;
        int offset = 0;
        int i = 0;
        byte[] mask = new byte[desiredLength];
        byte[] temp = new byte[seedLength + 4];
        System.arraycopy(seed, seedOffset, temp, 4, seedLength);
        while (offset < desiredLength) {
            temp[0] = (byte) (i >>> 24);
            temp[1] = (byte) (i >>> 16);
            temp[2] = (byte) (i >>> 8);
            temp[3] = (byte) i;
            int remaining = desiredLength - offset;
            System.arraycopy(SHA256(temp), 0, mask, offset, remaining < hLen ? remaining : hLen);
            offset = offset + hLen;
            i = i + 1;
        }
        return mask;
    }
    public static final SecureRandom random = new SecureRandom();
    public static byte[] SHA256(byte[] input){
        try{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
        }catch(Exception e){return null;}
    }
    public static String pad(String pre_message, String params, int length){
        byte[] message = pre_message.getBytes();
        int message_length = message.length;
        int h = 32;
        if (message_length > length - (h << 1) - 1) {
            return null;
        }
        int zeroPad = length - message_length - (h << 1) - 1;
        byte[] dataBlock = new byte[length - h];
        System.arraycopy(SHA256(params.getBytes()), 0, dataBlock, 0, h);
        System.arraycopy(message, 0, dataBlock, h + zeroPad + 1, message_length);
        dataBlock[h + zeroPad] = 1;
        byte[] seed = new byte[h];
        random.nextBytes(seed);
        byte[] dataBlockMask = MGF1(seed, 0, h, length - h);
        for (int i = 0; i < length - h; i++) {
            dataBlock[i] ^= dataBlockMask[i];
        }
        byte[] seedMask = MGF1(dataBlock, 0, length - h, h);
        for (int i = 0; i < h; i++) {
            seed[i] ^= seedMask[i];
        }
        byte[] padded = new byte[length];
        System.arraycopy(seed, 0, padded, 0, h);
        System.arraycopy(dataBlock, 0, padded, h, length - h);
        return bytesToHex(padded);
    }
    
    public static byte[] unpad(String pre_message, String params){
        byte[] message = hexToBytes(pre_message);
        int mLen = message.length;
        int hLen = 32;
        if (mLen < (hLen << 1) + 1) {
            return null;
        }
        byte[] copy = new byte[mLen];
        System.arraycopy(message, 0, copy, 0, mLen);
        byte[] seedMask = MGF1(copy, hLen, mLen - hLen, hLen);
        for (int i = 0; i < hLen; i++) {
            copy[i] ^= seedMask[i];
        }
        byte[] paramsHash = SHA256(params.getBytes());
        byte[] dataBlockMask = MGF1(copy, 0, hLen, mLen - hLen);
        int index = -1;
        for (int i = hLen; i < mLen; i++) {
            copy[i] ^= dataBlockMask[i - hLen];
            if (i < (hLen << 1)) {
                if (copy[i] != paramsHash[i - hLen]) {
                    return null;
                }
            } else if (index == -1) {
                if (copy[i] == 1) {
                    index = i + 1;
                }
            }
        }
        if (index == -1 || index == mLen) {
            return null;
        }
        byte[] unpadded = new byte[mLen - index];
        System.arraycopy(copy, index, unpadded, 0, mLen - index);
        return unpadded;
    }
}
