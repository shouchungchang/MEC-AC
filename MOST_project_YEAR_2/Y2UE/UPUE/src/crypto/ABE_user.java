package crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/*---------- attribute/policy setting: 2:wildcard, 1:positive, 0:negative ----------*/
//All index starts from 0

public class ABE_user{
	
	private Pairing pairing;
	public Field zr;
	public Field gt;
	public Element g;
    private static int n=0;
    public Element SK[][];
	public Element MPK[][];
	public Element proof_secret[] = new Element[5];
	public Element challenge1;
	public Element challenge2[] = new Element[2];	
	
	private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int SALT_LENGTH_BYTE = 16;
    private static final int IV_LENGTH_BYTE = 12;
    private static final Charset UTF_8 = StandardCharsets.UTF_8;
    
	public ABE_user(int max_wildcards, String curve_path) throws Exception {//max_wildcards = N_1
			pairing = PairingFactory.getPairing(curve_path);
			this.zr = pairing.getZr();//Zp
			this.gt = pairing.getGT();//GT
			this.n = max_wildcards + 3;
			this.MPK = new Element[13][n];
			this.SK = new Element[6][n];
	}
	
	public Element[][] encrypt(int[] policy, Element M, Element[][] MPK) throws Exception{// policy index 1-N1
		//return CT = (CA, CB, C1i, C2i, C3i, C4i, Cm, UV.Token)
		//M = AES secret key (plaintext of ABE)
		/*---------- get the position of positive, negative, wildcard ----------*/
		long ABE_Enc_time1 = System.currentTimeMillis();
		List<Integer> wildcard_position = new ArrayList<>();
		List<Integer> positive_position = new ArrayList<>();
		List<Integer> negative_position = new ArrayList<>();
		int cnt = 0;
		for(int i=0; i<policy.length; i++) {
			if(policy[i]==2) {//wildcard
				cnt++;
				wildcard_position.add(i+1);
				//System.out.println(i);
			}
			else if(policy[i]==1) {//positive
				positive_position.add(i+1);
			}
			else if(policy[i]==0) {//negative
				negative_position.add(i+1);
			}
		}
		if(cnt>n) {
			System.out.println("Too much wildcard!");
			return null;
		}
		/*---------- calculate a0 ~ an1 to get vector v ----------*/
		int[] wildcard_pos = new int[cnt];
		for(int i=0; i<cnt; i++) {
			wildcard_pos[i] = wildcard_position.get(i);// index starts from 0
		}

		Element v[] = new Element[n];// index : 1~n
		for(int i=0; i<n; i++) {
			v[i] = zr.newElement(0);
		}
		
		BigInteger a[] = vietaFormula(wildcard_pos, cnt);
		for(int i=0; i<a.length; i++) {
			v[i].set(a[i]).getImmutable();
		}
		
		/*---------- calculate Pi V,Z ----------*/
		BigInteger V = BigInteger.valueOf(0);
		BigInteger Z = BigInteger.valueOf(0);
			
		for(int positive_element:positive_position) {
			BigInteger tmp = BigInteger.valueOf(1);
			for(int wildcard_element:wildcard_position) {
				tmp = tmp.multiply(BigInteger.valueOf(positive_element).subtract(BigInteger.valueOf(wildcard_element))).mod((zr.getOrder()));
			}
			V = V.add(tmp);
		}
			
		for(int negative_element:negative_position) {
			BigInteger tmp = BigInteger.valueOf(1);
			for(int wildcard_element:wildcard_position) {
				tmp = tmp.multiply(BigInteger.valueOf(negative_element).subtract(BigInteger.valueOf(wildcard_element))).mod((zr.getOrder()));
			}
			Z = Z.add(tmp);
		}
		Z = Z.multiply(BigInteger.valueOf(-1)).mod((zr.getOrder()));
		/*----------end of calculate Pi V,Z----------*/
		
		v[n-2].set(V);
		v[n-1].set(Z);
		/*----------end of getting vector v----------*/
		
		Element CT[][] = new Element[8][n];
		Element s1 = zr.newRandomElement().getImmutable();
		Element s2 = zr.newRandomElement().getImmutable();
		Element alpha = zr.newRandomElement().getImmutable();
		Element beta = zr.newRandomElement().getImmutable();
		Element tau = zr.newRandomElement().getImmutable();
		
		proof_secret[0] = s1.duplicate();
		proof_secret[1] = s2.duplicate();
		proof_secret[2] = alpha.duplicate();
		proof_secret[3] = beta.duplicate();
		proof_secret[4] = tau.duplicate();
		
		Element CA = MPK[0][0].duplicate().powZn(s2);	//g^{s2}
		Element CB = MPK[1][0].duplicate().powZn(s1);	//g1^{s1}
		Element C1i[] = new Element[n];
		Element C2i[] = new Element[n];
		Element C3i[] = new Element[n];
		Element C4i[] = new Element[n];
		
		/*---------- calculate C_1,i ~ C_4,i ----------*/
		//for(int i=0; i<n; i++) {
		//	C1i[i] = (MPK[3][i].powZn(s1)).mul(MPK[7][i].powZn(s2)).mul(MPK[11][1].powZn(v[i].mul(alpha)));
		//	C2i[i] = (MPK[4][i].powZn(s1)).mul(MPK[8][i].powZn(s2)).mul(MPK[11][2].powZn(v[i].mul(alpha)));
		//	C3i[i] = (MPK[5][i].powZn(s1)).mul(MPK[9][i].powZn(s2)).mul(MPK[12][1].powZn(v[i].mul(beta)));
		//	C4i[i] = (MPK[6][i].powZn(s1)).mul(MPK[10][i].powZn(s2)).mul(MPK[12][2].powZn(v[i].mul(beta)));
		//}
		
		/*test*/
		
		Element U1i[] = new Element[n];Element U2i[] = new Element[n];
		Element W1i[] = new Element[n];Element W2i[] = new Element[n];
		Element T1i[] = new Element[n];Element T2i[] = new Element[n];
		Element Z1i[] = new Element[n];Element Z2i[] = new Element[n];
		Element V1=MPK[11][0].duplicate().getImmutable();Element V2=MPK[11][1].duplicate().getImmutable();
		Element X1=MPK[12][0].duplicate().getImmutable();Element X2=MPK[12][1].duplicate().getImmutable();
		for(int i=0; i<n; i++) {
			U1i[i]=MPK[3][i].duplicate().getImmutable();U2i[i]=MPK[4][i].duplicate().getImmutable();
			W1i[i]=MPK[5][i].duplicate().getImmutable();W2i[i]=MPK[6][i].duplicate().getImmutable();
			T1i[i]=MPK[7][i].duplicate().getImmutable();T2i[i]=MPK[8][i].duplicate().getImmutable();
			Z1i[i]=MPK[9][i].duplicate().getImmutable();Z2i[i]=MPK[10][i].duplicate().getImmutable();
		}
		for(int i=0; i<n; i++) {
			C1i[i]=(U1i[i].duplicate().powZn(s1)).mul(T1i[i].duplicate().powZn(s2)).mul(V1.duplicate().powZn(v[i].duplicate().mul(alpha))).getImmutable();
			C2i[i]=(U2i[i].duplicate().powZn(s1)).mul(T2i[i].duplicate().powZn(s2)).mul(V2.duplicate().powZn(v[i].duplicate().mul(alpha))).getImmutable();
			C3i[i]=(W1i[i].duplicate().powZn(s1)).mul(Z1i[i].duplicate().powZn(s2)).mul(X1.duplicate().powZn(v[i].duplicate().mul(beta))).getImmutable();
			C4i[i]=(W2i[i].duplicate().powZn(s1)).mul(Z2i[i].duplicate().powZn(s2)).mul(X2.duplicate().powZn(v[i].duplicate().mul(beta))).getImmutable();
		}
		
		/*----------  calculate C_m ----------*/
		Element Cm = MPK[2][0].duplicate().powZn(s2.duplicate()).mul(M.duplicate()).getImmutable();
		Element[] UV_Token = new Element[2];
		UV_Token[0] = Cm.duplicate().powZn(tau.duplicate()).getImmutable();
		UV_Token[1] = s2.duplicate().mul(tau.duplicate()).getImmutable();
		
		CT[0][0] = CA.duplicate();
		CT[1][0] = CB.duplicate();
		for(int i=0; i<n; i++) {
			CT[2][i] = C1i[i].duplicate();
			CT[3][i] = C2i[i].duplicate();
			CT[4][i] = C3i[i].duplicate();
			CT[5][i] = C4i[i].duplicate();
		}
		CT[6][0] = Cm.duplicate();
		CT[7][0] = UV_Token[0].duplicate();
		CT[7][1] = UV_Token[1].duplicate();
		long ABE_Enc_time2 = System.currentTimeMillis() - ABE_Enc_time1;
		//System.out.println("ABE Enc time (computer):" + ABE_Enc_time2);
		System.out.println("ABE Enc time:" + ABE_Enc_time2 + "ms");
		return CT;
	}

	public Element decrypt(Element[][] SK, Element[][] CT) throws Exception{
		long ABE_Dec_time1 = System.currentTimeMillis();
		//attkey (SK) = {KA, KB, K1i, K2i, K3i, K4i}
		//ciphertext (CT) = {CA, CB, C1i, C2i, C3i, C4i, Cm}
		//return the secret key of AES
		int n = CT[2].length;// C_1i's size
		if(SK[2].length!=n) {
			System.out.println("Size error!!");
			return null;
		}
		Element Cm = CT[6][0].duplicate();
		Element CA_KA = pairing.pairing(CT[0][0].duplicate(), SK[0][0].duplicate()).getImmutable();
		Element CB_KB = pairing.pairing(CT[1][0].duplicate(), SK[1][0].duplicate()).getImmutable();
		Element tmp = null;
		Element K1i[] = new Element[n];Element K2i[] = new Element[n];Element K3i[] = new Element[n];Element K4i[] = new Element[n];
		Element C1i[] = new Element[n];Element C2i[] = new Element[n];Element C3i[] = new Element[n];Element C4i[] = new Element[n];
		
		for(int i=0; i<n; i++) {
			K1i[i] = SK[2][i].duplicate().getImmutable();
			K2i[i] = SK[3][i].duplicate().getImmutable();
			K3i[i] = SK[4][i].duplicate().getImmutable();
			K4i[i] = SK[5][i].duplicate().getImmutable();
			C1i[i] = CT[2][i].duplicate().getImmutable();
			C2i[i] = CT[3][i].duplicate().getImmutable();
			C3i[i] = CT[4][i].duplicate().getImmutable();
			C4i[i] = CT[5][i].duplicate().getImmutable();
		}
		
		for(int i=0; i<n; i++) {
			if(i==0) {
				tmp = pairing.pairing(C1i[i].duplicate(), K1i[i].duplicate());
			}
			else {
				tmp = tmp.duplicate().mul(pairing.pairing(C1i[i].duplicate(), K1i[i].duplicate()));
			}
		}
		for(int i=0; i<n; i++) {
			tmp = tmp.duplicate().mul(pairing.pairing(C2i[i].duplicate(), K2i[i].duplicate()));
			tmp = tmp.duplicate().mul(pairing.pairing(C3i[i].duplicate(), K3i[i].duplicate()));
			tmp = tmp.duplicate().mul(pairing.pairing(C4i[i].duplicate(), K4i[i].duplicate()));
		}
		
		Element M = Cm.duplicate().div(CA_KA.duplicate().mul(CB_KB.duplicate()).mul(tmp.duplicate()));
		//System.out.println("427:"+ M);
		long ABE_Dec_time2 = System.currentTimeMillis() - ABE_Dec_time1;
		//System.out.println("ABE Dec time (computer):" + ABE_Dec_time2);
		System.out.println("ABE Dec time:" + ABE_Dec_time2 + "ms");
		return M;
	}

	public Element OwnershipVerRespTokenGen(Element[] proof_secret, Element OSVReqToken) {
		long tmp_time1 = System.currentTimeMillis();
		Element s1 = proof_secret[0].duplicate().getImmutable();
		Element OVRespToken = OSVReqToken.duplicate().powZn(s1.duplicate());
		long tmp_time2 = System.currentTimeMillis() - tmp_time1;
		//System.out.println("OwnershipVerRespTokenGen time (computer):"+tmp_time2);
		System.out.println("OwnershipVerRespTokenGen time:" + tmp_time2 + "ms");
		return OVRespToken;
	}

	public Element[] AttributeVerRespTokenGen(Element[][] AVReqToken, Element[] proof_secret, Element[][] SK) throws Exception{
		long tmp_time1 = System.currentTimeMillis();
		Element M_prime = decrypt(SK, AVReqToken);
		Element AVRespToken[] = new Element[2];
		Element resp1 = M_prime.duplicate().powZn(proof_secret[4]).getImmutable();
		Element resp2 = AVReqToken[6][0].duplicate().powZn(proof_secret[4]).getImmutable();
		AVRespToken[0] = resp1.duplicate();
		AVRespToken[1] = resp2.duplicate();
		long tmp_time2 = System.currentTimeMillis() - tmp_time1;
		//System.out.println("AttributeVerRespTokenGen time (computer):" + tmp_time2);
		System.out.println("AttributeVerRespTokenGen time:" + tmp_time2 + "ms");
		return AVRespToken;
	}

	/*-------------- math tools --------------*/
	public BigInteger[] hide_positive_attribute(BigInteger[] attribute) {//X_V
		BigInteger[] hide_positive_attribute = new BigInteger[n];//n=5
		for(int i=0; i<n; i++) {
			hide_positive_attribute[i] = BigInteger.valueOf(0);
		}
		hide_positive_attribute[n-2] = BigInteger.valueOf(1);
		hide_positive_attribute[n-1] = BigInteger.valueOf(0);
		for(int i=0; i<n-2; i++) {//X_V index 0-2
			for(int j=0; j<attribute.length; j++) {// {+,-,-,+} index 0-3
				if(attribute[j].equals(BigInteger.valueOf(1))) {
					hide_positive_attribute[i] = (hide_positive_attribute[i].add(BigInteger.valueOf(j+1).pow(i))).mod((zr.getOrder()));//attribute position starts from 1, not 0 -> j+1
				}
			}
			hide_positive_attribute[i] = (hide_positive_attribute[i].multiply(BigInteger.valueOf(-1))).mod(zr.getOrder());
		}
		return hide_positive_attribute;
	}
	public BigInteger[] hide_negative_attribute(BigInteger[] attribute) {//X_Z
		BigInteger[] hide_negative_attribute = new BigInteger[n];
		for(int i=0; i<n; i++) {
			hide_negative_attribute[i] = BigInteger.valueOf(0);
		}
		hide_negative_attribute[n-2] = BigInteger.valueOf(0);
		hide_negative_attribute[n-1] = BigInteger.valueOf(1);
		for(int i=0; i<n-2; i++) {
			for(int j=0; j<attribute.length; j++) {
				if(attribute[j].equals(BigInteger.valueOf(0))) {
					hide_negative_attribute[i] = (hide_negative_attribute[i].add(BigInteger.valueOf(j+1).pow(i))).mod((zr.getOrder()));//attribute position starts from 1, not 0 -> j+1
				}
			}
		}
		return hide_negative_attribute;
	}
	public static BigInteger[] vietaFormula(int wildcard_pos[], int wildcard_cnt)
	{
	    wildcard_cnt++;
		BigInteger coeff[] = new BigInteger[wildcard_cnt + 1];
	    
	    for(int i=0; i<coeff.length; i++) {
	    	coeff[i] = BigInteger.valueOf(0);
	    }
	    
	    // Set highest order coefficient as 1
	    coeff[wildcard_cnt] = BigInteger.valueOf(1);
	 
	    for (int i=1; i<wildcard_cnt; i++) {
	        for (int j = wildcard_cnt-i-1; j<wildcard_cnt; j++) {
	            coeff[j] = coeff[j].add(BigInteger.valueOf(-1).multiply(BigInteger.valueOf(wildcard_pos[i-1])).multiply(coeff[j+1]));
	        }
	    }
	    
	    BigInteger a[] = new BigInteger[coeff.length-1];
	    for(int i=1; i<coeff.length; i++) {
	    	a[i-1] = coeff[i];
	    }
	    
	    return a;
	}
	
	
	/*--------------------AES--------------------*/
	
	private static byte[] AES_Enc(byte[] plainText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] encryptedText = cipher.doFinal(plainText);
        return encryptedText;
    }
	
    public static String encryptWithPrefixIV(byte[] plainText, SecretKey secret, byte[] iv) throws Exception {
    	//return base64 CT and AES parameters
        byte[] cipherText = AES_Enc(plainText, secret, iv);

        byte[] cipherTextWithIv = ByteBuffer.allocate(iv.length + cipherText.length)
                .put(iv)
                .put(cipherText)
                .array();
        return Base64.getEncoder().encodeToString(cipherTextWithIv);
    }
	
    private static String AES_Dec(byte[] cipherText, SecretKey secret, byte[] iv) throws Exception {

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secret, new GCMParameterSpec(TAG_LENGTH_BIT, iv));
        byte[] plainText = cipher.doFinal(cipherText);
        return new String(plainText, UTF_8);
    }
    
    public static String decryptWithPrefixIV(String cipherText, SecretKey secret) throws Exception {

    	byte[] decode = Base64.getDecoder().decode(cipherText.getBytes(UTF_8));
    	
        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);
        //bb.get(iv, 0, iv.length);

        byte[] cipherText_byte = new byte[bb.remaining()];
        bb.get(cipherText_byte);

        String plainText = AES_Dec(cipherText_byte, secret, iv);
        return plainText;
    }
    
    // AES Encrypt function
    public static String pwd_encrypt(String plainText, String password) throws Exception {

        // 16 bytes salt
        byte[] salt = getRandomNonce(SALT_LENGTH_BYTE);

        // GCM recommended 12 bytes iv
        byte[] iv = getRandomNonce(IV_LENGTH_BYTE);

        // secret key from password
        // the password is the M of ABE
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        // ASE-GCM needs GCMParameterSpec
        cipher.init(Cipher.ENCRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] cipherText = cipher.doFinal(plainText.getBytes());

        // prefix IV and Salt to cipher text
        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length)
                .put(iv)
                .put(salt)
                .put(cipherText)
                .array();

        // string representation, base64, send this string to other for decryption.
        return Base64.getEncoder().encodeToString(cipherTextWithIvSalt);
    }

    // AES decrypt function
    public static String pwd_decrypt(String cipherText, String password) throws Exception {
        byte[] decode = Base64.getDecoder().decode(cipherText.getBytes(UTF_8));

        // get back the iv and salt from the cipher text
        ByteBuffer bb = ByteBuffer.wrap(decode);

        byte[] iv = new byte[IV_LENGTH_BYTE];
        bb.get(iv);

        byte[] salt = new byte[SALT_LENGTH_BYTE];
        bb.get(salt);

        byte[] cipherText_byte = new byte[bb.remaining()];
        bb.get(cipherText_byte);

        // get back the aes key from the same password and salt
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password.toCharArray(), salt);

        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGO);

        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] plainText = cipher.doFinal(cipherText_byte);

        return new String(plainText, UTF_8);
    }
    
	/*-------------------Tools-------------------*/
	
	public static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }
	
	public static SecretKey getAESKeyFromPassword(char[] password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        // iterationCount = 65536
        // keyLength = 256
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }
	
}

