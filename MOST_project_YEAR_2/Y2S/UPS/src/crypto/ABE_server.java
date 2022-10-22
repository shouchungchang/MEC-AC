package crypto;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
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
import javax.servlet.ServletContext;

//import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/*---------- attribute/policy setting: 2:wildcard, 1:positive, 0:negative ----------*/
//All index starts from 0

public class ABE_server{
	
	public Pairing pairing;
	public Field zr;
	public Field gt;
	public Field g1;
	public Element g;
    private static int n;
	public Element MPK[][];
	public Element MSK[][];
	public Element proof_secret[] = new Element[5];
	public Element challenge1;
	public Element challenge2[] = new Element[2];
    
	public ABE_server(int max_wildcards, String curve_path) throws Exception {//max_wildcards = N_1
		pairing = PairingFactory.getPairing(curve_path);
		zr = pairing.getZr();//Zp
		gt = pairing.getGT();//GT
		g1 = pairing.getG1();//G1
		g = g1.newRandomElement().getImmutable();
		n = max_wildcards + 3;
		this.MPK = new Element[13][n];
		this.MSK = new Element[11][n];
	}
	
	public void setup() throws Exception {
		
		/*---------- variables initialization ----------*/
		Element gamma1 = zr.newRandomElement().getImmutable();
		Element gamma2 = zr.newRandomElement().getImmutable();
		Element theta1 = zr.newRandomElement().getImmutable();
		Element theta2 = zr.newRandomElement().getImmutable();
		Element u1i[] = new Element[n];Element u2i[] = new Element[n];
		Element w1i[] = new Element[n];Element w2i[] = new Element[n];
		Element t1i[] = new Element[n];Element t2i[] = new Element[n];
		Element z1i[] = new Element[n];Element z2i[] = new Element[n];
		Element delta=zr.newRandomElement().getImmutable();
		
		/*---------- parameters initialization ----------*/
		for(int i=0; i<n; i++) {//0 - n-1
			u1i[i] = zr.newRandomElement().getImmutable();
			w1i[i] = zr.newRandomElement().getImmutable();
			t1i[i] = zr.newRandomElement().getImmutable();
			t2i[i] = zr.newRandomElement().getImmutable();
			z1i[i] = zr.newRandomElement().getImmutable();
			z2i[i] = zr.newRandomElement().getImmutable();
		}
		
		for(int i=0; i<n; i++) {
			u2i[i] = ((delta.duplicate().add(gamma2.duplicate().mul(u1i[i].duplicate()))).div(gamma1.duplicate())).getImmutable();
			w2i[i] = ((delta.duplicate().add(theta2.duplicate().mul(w1i[i].duplicate()))).div(theta1.duplicate())).getImmutable();
		}
		
		Element g1 = (g.duplicate().powZn(delta.duplicate())).getImmutable();
		Element g2 = pairing.getG1().newRandomElement().getImmutable();
		
		/*---------- MPK ----------*/
		MPK[0][0] = g.duplicate().getImmutable();									//g
		MPK[1][0] = g1.duplicate().getImmutable();									//g1
		MPK[2][0] = pairing.pairing(g.duplicate(),g2.duplicate()).getImmutable();	//Y = e(g,g2)

		for(int i=0; i<n; i++) {
			MPK[3][i] = g.duplicate().powZn(u1i[i].duplicate()).getImmutable(); 	//U1,i
			MPK[4][i] = g.duplicate().powZn(u2i[i].duplicate()).getImmutable();  	//U2,i
			MPK[5][i] = g.duplicate().powZn(w1i[i].duplicate()).getImmutable(); 	//W1,i
			MPK[6][i] = g.duplicate().powZn(w2i[i].duplicate()).getImmutable(); 	//W2,i
			MPK[7][i] = g.duplicate().powZn(t1i[i].duplicate()).getImmutable(); 	//T1,i
			MPK[8][i] = g.duplicate().powZn(t2i[i].duplicate()).getImmutable(); 	//T2,i
			MPK[9][i] = g.duplicate().powZn(z1i[i].duplicate()).getImmutable();		//Z1,i
			MPK[10][i] = g.duplicate().powZn(z2i[i].duplicate()).getImmutable(); 	//Z2,i
		}
	    
		MPK[11][0] = g.duplicate().powZn(gamma1.duplicate()).getImmutable();    	//V1
		MPK[11][1] = g.duplicate().powZn(gamma2.duplicate()).getImmutable();   		//V2
		MPK[12][0] = g.duplicate().powZn(theta1.duplicate()).getImmutable(); 		//X1
		MPK[12][1] = g.duplicate().powZn(theta2.duplicate()).getImmutable();  		//X2

		/*---------- MSK ----------*/
		MSK[0][0]=g2;
		for(int i=0; i<n; i++) {
			MSK[1][i] = u1i[i].duplicate().getImmutable(); 				//u1,i
			MSK[2][i] = u2i[i].duplicate().getImmutable();				//u2,i
			MSK[3][i] = t1i[i].duplicate().getImmutable();				//t1,i
			MSK[4][i] = t2i[i].duplicate().getImmutable();				//t2,i
			MSK[5][i] = w1i[i].duplicate().getImmutable();				//w1,i
			MSK[6][i] = w2i[i].duplicate().getImmutable();				//w2,i
			MSK[7][i] = z1i[i].duplicate().getImmutable();				//z1,i
			MSK[8][i] = z2i[i].duplicate().getImmutable();				//z2,i
	    }
		MSK[9][0] = gamma1.duplicate().getImmutable();					//gamma1
		MSK[9][1] = gamma2.duplicate().getImmutable();					//gamma2
		MSK[10][0] = theta1.duplicate().getImmutable();					//theta1
		MSK[10][1] = theta2.duplicate().getImmutable();					//theta2
	}
	
	public Element[][] KeyGen(Element[][] MSK, BigInteger[] attribute) throws Exception {
		//return user's attribute key {K_A,K_B,K_1,i ~ K_4,i}
		//init
		Element key[][] = new Element[6][n];
		BigInteger Xv[] = hide_positive_attribute(attribute);
		BigInteger Xz[] = hide_negative_attribute(attribute);
		Element V[] = new Element[n];
		Element Z[] = new Element[n];
		for(int i=0; i<n; i++) {
			V[i] = zr.newElement(Xv[i]).getImmutable();
			Z[i] = zr.newElement(Xz[i]).getImmutable();
		}
		Element r1i[] = new Element[n];
		Element r2i[] = new Element[n];
		Element f1 = zr.newRandomElement().getImmutable();
		Element f2 = zr.newRandomElement().getImmutable();
		Element K1i[] = new Element[n];
		Element K2i[] = new Element[n];
		Element K3i[] = new Element[n];
		Element K4i[] = new Element[n];
		Element g2 = MSK[0][0].duplicate().getImmutable();
		Element KA = null;
		Element KB = null;
		Element u1i[] = new Element[n];
		Element u2i[] = new Element[n];
		Element t1i[] = new Element[n];
		Element t2i[] = new Element[n];
		Element w1i[] = new Element[n];
		Element w2i[] = new Element[n];
		Element z1i[] = new Element[n];
		Element z2i[] = new Element[n];
		 
		/*----------  getting parameters ----------*/
		for(int i=0; i<n; i++) {
			u1i[i] = MSK[1][i].duplicate().getImmutable();
			u2i[i] = MSK[2][i].duplicate().getImmutable();
			t1i[i] = MSK[3][i].duplicate().getImmutable();
			t2i[i] = MSK[4][i].duplicate().getImmutable();
			w1i[i] = MSK[5][i].duplicate().getImmutable();
			w2i[i] = MSK[6][i].duplicate().getImmutable();
			z1i[i] = MSK[7][i].duplicate().getImmutable();
			z2i[i] = MSK[8][i].duplicate().getImmutable();
			r1i[i] = zr.newRandomElement().getImmutable();
			r2i[i] = zr.newRandomElement().getImmutable();
		}
		
		Element gamma1 = MSK[9][0].duplicate().getImmutable();
		Element gamma2 = MSK[9][1].duplicate().getImmutable();
		Element theta1 = MSK[10][0].duplicate().getImmutable();
		Element theta2 = MSK[10][1].duplicate().getImmutable();
		/*---------- ---------- ----------*/
		
		
		/*---------- key generation ----------*/
		for(int i=0; i<n; i++) {
			K1i[i] = g.duplicate().powZn(f1.duplicate().mul(V[i].duplicate()).mul(u2i[i].duplicate()).sub(gamma2.duplicate().mul(r1i[i].duplicate())));//K1i
			K2i[i] = g.duplicate().powZn(gamma1.duplicate().mul(r1i[i].duplicate()).sub(f1.duplicate().mul(V[i].duplicate()).mul(u1i[i].duplicate())));//K2i
			K3i[i] = g.duplicate().powZn(f2.duplicate().mul(Z[i].duplicate()).mul(w2i[i].duplicate()).sub(theta2.duplicate().mul(r2i[i].duplicate())));//K3i
			K4i[i] = g.duplicate().powZn(theta1.duplicate().mul(r2i[i].duplicate()).sub(f2.duplicate().mul(Z[i].duplicate()).mul(w1i[i].duplicate())));//K4i
		}
		
		
		//KA, KB
		Element tmp = null;
		for(int i=0; i<n; i++) {
			if(i==0) {
				tmp = (K1i[i].duplicate().powZn(t1i[i].duplicate().mul(-1))).mul(K2i[i].duplicate().powZn(t2i[i].duplicate().mul(-1)))
						.mul(K3i[i].duplicate().powZn(z1i[i].duplicate().mul(-1))).mul(K4i[i].duplicate().powZn(z2i[i].duplicate().mul(-1)));
			}
			else {
				tmp = tmp.duplicate().mul(K1i[i].duplicate().powZn(t1i[i].duplicate().mul(-1))).mul(K2i[i].duplicate().powZn(t2i[i].duplicate().mul(-1)))
						.mul(K3i[i].duplicate().powZn(z1i[i].duplicate().mul(-1))).mul(K4i[i].duplicate().powZn(z2i[i].duplicate().mul(-1)));
			}
		}
		KA = g2.duplicate().mul(tmp.duplicate()).getImmutable();
		
		for(int i=0; i<n; i++) {
			if(i==0) {
				tmp = g.duplicate().powZn((r1i[i].duplicate().add(r2i[i].duplicate()).mul(-1)));
			}
			else {
				tmp = tmp.duplicate().mul(g.duplicate().powZn((r1i[i].duplicate().add(r2i[i].duplicate()).mul(-1))));
			}
		}
		KB = tmp.duplicate().getImmutable();
		
		key[0][0] = KA.duplicate().getImmutable();//KA
		key[1][0] = KB.duplicate().getImmutable();//KB
		
		for(int i=0 ; i<n ; i++) {
			key[2][i] = K1i[i].duplicate().getImmutable();//K1i
			key[3][i] = K2i[i].duplicate().getImmutable();//k2i
			key[4][i] = K3i[i].duplicate().getImmutable();//K3i
			key[5][i] = K4i[i].duplicate().getImmutable();//K4i
		}
		
		//SK = {KA,KB,K1i,K2i,K3i,K4i}
		return key;
	}
	
	public Element OwnershipVerReqTokenGen(Element[][] MPK, Element pi, Element[][]CT) {
		if(!(CT[0][0].getField().equals(g.getField()))) {
			System.out.println("CA does not belong to field G!!");
			return null;
		}
		if(!(CT[1][0].getField().equals(g.getField()))) {
			System.out.println("CB does not belong to field G!!");
			return null;
		}
		for(int i=0; i<n; i++) {
			if(!(CT[2][i].getField().equals(g.getField()))) {System.out.println("C1," + String.valueOf(i) +" does not belong to field G!!"); return null;}
			if(!(CT[3][i].getField().equals(g.getField()))) {System.out.println("C2," + String.valueOf(i) +" does not belong to field G!!"); return null;}
			if(!(CT[4][i].getField().equals(g.getField()))) {System.out.println("C3," + String.valueOf(i) +" does not belong to field G!!"); return null;}
			if(!(CT[5][i].getField().equals(g.getField()))) {System.out.println("C4," + String.valueOf(i) +" does not belong to field G!!"); return null;}
		}
		
		//Element pi = zr.newRandomElement().getImmutable();
		challenge1 = pi.duplicate().getImmutable();
		Element g1 = MPK[1][0].duplicate().getImmutable();
		Element OVReqToken = g1.duplicate().powZn(pi.duplicate()).getImmutable();
		return OVReqToken;
	}
	
	public boolean OwnershipVer(Element[][] CT, Element challenge_1, Element OVRespToken) {
		Element CB = CT[1][0].duplicate().getImmutable();
		Element compare_value = CB.duplicate().powZn(challenge_1.duplicate());
		if(OVRespToken.equals(compare_value)) {
			System.out.println("Ownership verification: True");
			return true;
		}

		else {
			System.out.println("Ownership verification: False");
			return false;
		}
	}
	
	public Element[][] AttributeVerReqTokenGen(Element[][] CT, Element sigma, Element rho){
		//CT = {CA, CB, C1i, C2i, C3i, C4i, Cm, UV.Token}

		//Element sigma = zr.newRandomElement().getImmutable();
		//Element rho = zr.newRandomElement().getImmutable();
		challenge2[0] = sigma.duplicate().getImmutable();
		challenge2[1] = rho.duplicate().getImmutable();
		
		Element Cm_sigma = CT[6][0].duplicate().powZn(sigma.duplicate()).getImmutable();
		Element CA_p = CT[0][0].duplicate().powZn(rho.duplicate()).getImmutable();
		Element CB_p = CT[1][0].duplicate().powZn(rho.duplicate()).getImmutable();
		Element C1i_p[] = new Element[n];
		Element C2i_p[] = new Element[n];
		Element C3i_p[] = new Element[n];
		Element C4i_p[] = new Element[n];
		
		for(int i=0; i<n; i++) {
			C1i_p[i] = CT[2][i].duplicate().powZn(rho.duplicate()).getImmutable();
			C2i_p[i] = CT[3][i].duplicate().powZn(rho.duplicate()).getImmutable();
			C3i_p[i] = CT[4][i].duplicate().powZn(rho.duplicate()).getImmutable();
			C4i_p[i] = CT[5][i].duplicate().powZn(rho.duplicate()).getImmutable();
		}
		
		Element AVReqToken[][] = new Element[7][n];
		AVReqToken[0][0] = CA_p.duplicate();
		AVReqToken[1][0] = CB_p.duplicate();
		AVReqToken[6][0] = Cm_sigma.duplicate();
		for(int i=0; i<n; i++) {
			AVReqToken[2][i] = C1i_p[i].duplicate();
			AVReqToken[3][i] = C2i_p[i].duplicate();
			AVReqToken[4][i] = C3i_p[i].duplicate();
			AVReqToken[5][i] = C4i_p[i].duplicate();
		}

		return AVReqToken;
	}
		
	public boolean AttributeVer(Element[] AVRespToken, Element[][] CT, Element sigma, Element rho, Element[][] MPK) {
		//challenge2 = {sigma, rho}
		//UV.Token = {Cm^tau, s2*tau}
		Element UVT1 = CT[7][0].duplicate();
		Element UVT2 = CT[7][1].duplicate();
		Element result1 = UVT1.duplicate().powZn(sigma);
		Element result2 = AVRespToken[1];
		if(!result1.equals(result2)) {
			System.out.println("Attribute verification: False");
			return false;
		}
		Element Y_mod = MPK[2][0].duplicate().powZn(UVT2.duplicate().mul(rho.duplicate()).mul(-1));//Y^{-s2*tau*rho}
		Element result3 = Y_mod.duplicate().mul(result2);
		if(!result3.equals(AVRespToken[0])) {
			System.out.println("Attribute verification: False");
			return false;
		}
		System.out.println("Attribute verification: True");
		return true;
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
}

