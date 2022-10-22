package crypto;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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

import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

class test{
	public static String file_path = "D:\\Java\\ABE_parameters.txt";
	public static void main(String[] args) throws Exception{
		System.out.println("Start!");
		int n1=2;//wildcard numbers
		ABE abe = new ABE(n1);
		BigInteger one = BigInteger.valueOf(1);
		BigInteger zero = BigInteger.valueOf(0);
		// attribute: {1,0,0,0,1,0,0,0,1,0}
		BigInteger[] attr = {one,zero,zero,zero,one};
		Element[][] sk = abe.KeyGen(abe.MSK, attr);
		//encryption policy: access structure
		// 0: false, 1:true, 2:wildcard
		String pairing_filePath = "D:\\Java\\User_pairing_server\\User_pairing_server\\src\\main\\resources\\curves\\a.properties";

		Pairing pairing = PairingFactory.getPairing(pairing_filePath);
		/*
		int[] policy = {1,0,0,0,1};
		Pairing pairing = PairingFactory.getPairing("curves/a.properties");
		Element M = pairing.getGT().newRandomElement().getImmutable();
		System.out.println(Base64.getEncoder().encodeToString(M.toBytes()));
		Element[][] CT = abe.encrypt(policy, M, abe.MPK);
		Element M_prime = abe.decrypt(sk, CT);
		System.out.println(Base64.getEncoder().encodeToString(M_prime.toBytes()));
		*/
		
		//Element Cm = Y.duplicate().powZn(s2.duplicate()).mul(M.duplicate());
		//System.out.println(Cm);
		
		
		//test
		
		/*
		System.out.println(M);// Original M
		byte[] M_byte = M.toBytes();
		byte[] store_byte = new byte[128];
		String base64_ct = Base64.getEncoder().encodeToString(M_byte);
		System.out.println(base64_ct);*/
		/*
		FileReader fr = new FileReader(file_path);
		BufferedReader br = new BufferedReader(fr);
		byte[] test_b = Base64.getDecoder().decode(br.readLine());
		Element mpk_00 = pairing.getG1().newElementFromBytes(test_b).getImmutable();
		//System.out.println(mpk_00);
		br.close();*/
		
		
		//test ends
		
		
		
		
		
		//Element[][] CT = abe.encrypt(policy, M, abe.MPK, abe.MSK);
		//AES part
		//Element ans = abe.decrypt(sk, CT);
		
		//String s = ans.toString();
		//String test_m = "testtest123";
		//String AES_CT = abe.pwd_encrypt(test_m, M_S);
		//String AES_PT = abe.pwd_decrypt(AES_CT, s);
		
		//System.out.println("AES_plaintext=" + AES_PT);
		//System.out.println(s);
		
		/*
		Element OVReqToken = abe.OwnershipVerReqTokenGen(abe.MPK);
		Element OVRespToken = abe.OwnershipVerRespTokenGen(abe.proof_secret, OVReqToken);
		boolean OVresult = abe.OwnershipVer(CT, abe.challenge1, OVRespToken);
		
		Element AVReqToken[][] = abe.AttributeVerReqTokenGen(CT);
		Element AVRespToken[] = abe.AttributeVerRespTokenGen(AVReqToken, abe.proof_secret, sk);
		boolean AVresult = abe.AttributeVer(AVRespToken, CT, abe.challenge2, abe.MPK);
		*/
		//System.out.println("Test finished");
	}
}
