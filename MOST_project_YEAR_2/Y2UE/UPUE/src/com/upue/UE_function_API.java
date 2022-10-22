package com.upue;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import crypto.ABE_user;

public class UE_function_API {
	// For ABE
	public static int max_wildcards;
	//public static Pairing pairing;
	private static int n;
	public Element MPK[][];
	public Element SK[][];
	public Field zr;
	public Field g1;
	public Field gt;
	private static String filePath = "D:\\Java\\User_pairing_server\\User_pairing_server\\src\\main\\resources\\curves\\a.properties";
	private final static String newline_symbol = "\n";
	final private Pairing pairing = PairingFactory.getPairing(filePath);
	public ABE_user ABE;
	
	public UE_function_API(int max_wildcards) throws Exception {
		this.max_wildcards = max_wildcards;
		n = max_wildcards + 3;
		ABE = new ABE_user(this.max_wildcards, filePath);
		this.MPK = new Element[13][n];
		this.SK = new Element[6][n];
		this.g1 = pairing.getG1();
		this.gt = pairing.getGT();
		this.zr = pairing.getZr();
	}
	
	public Element[][] generate_CT(int[] policy, Element M) throws Exception {
		if(policy.length != n)return null;
		Element[][] CT = ABE.encrypt(policy, M, MPK);
		// UV.Token: CT[7][0] & CT[7][1]
		return CT;
	}
	
	public Element get_OSVRespToken(String OSVReqToken_s) {
		Element OSVReqToken = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(OSVReqToken_s));
		Element OSVResp_Token = ABE.OwnershipVerRespTokenGen(ABE.proof_secret, OSVReqToken);
		return OSVResp_Token;
	}
	
	public Element[] get_AVRespToken(String AVReq_Token_s) throws Exception {
		Element[][] CT_prime = new Element[7][n];// Without UVToken
		String[] data = AVReq_Token_s.split("#");
		int cnt = 0;
		
		// Convert AVReqToken from String to Element[][]
		CT_prime[0][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
		CT_prime[1][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
		for(int i=0; i<n; i++) {
			CT_prime[2][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
			CT_prime[3][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
			CT_prime[4][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
			CT_prime[5][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
		}
		CT_prime[6][0] = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));
		
		// Generate AVRespToken
		Element[] AVRespToken = ABE.AttributeVerRespTokenGen(CT_prime, ABE.proof_secret, SK);
		return AVRespToken;
	}
	
	public Element decrypt(String CT_s) throws Exception {
		// Convert CT from String to Element[][] (without UVToken)
		Element[][] CT = new Element[7][n];
		String[] data = CT_s.split("#");
		int cnt = 0;
		
		// Convert CT from String to Element
		CT[0][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
		CT[1][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
		for(int i=0; i<n; i++) {
			CT[2][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
			CT[3][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
			CT[4][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
			CT[5][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));cnt++;
		}
		CT[6][0] = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(data[cnt]));//Cm
		Element M = ABE.decrypt(SK, CT);
		return M;
	}
	
	public String Request_MPK(String URL) {
		HttpPost httpPost = new HttpPost(URL);
		HttpClient httpClient = new DefaultHttpClient();
		try {
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
            nameValuePairs.add(new BasicNameValuePair("msg","MPK"));
            httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            // Response
            HttpResponse UPS_response = httpClient.execute(httpPost);
            // MPK string format
            final String MPK_string = EntityUtils.toString(UPS_response.getEntity());
            return MPK_string;
		}
		catch(Exception e) {
			System.out.println("MPK request failed.");
		}
		return null;
	}
	
	public void write_MPK_string_to_file(String MPK_s, String filePath) throws IOException {
		String[] data = MPK_s.split("#");
		FileWriter out = new FileWriter(filePath, true);
		for(int i=0; i<data.length; i++) {
			out.write(data[i]);out.write(newline_symbol);
		}
    	out.close();
	}
	
	public void convert_MPK_string_to_Element(String MPK_s){
		String[] data = MPK_s.split("#");
		int cnt = 0;
		MPK[0][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		MPK[1][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		MPK[2][0] = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		for(int i=0; i<n; i++) {
			MPK[3][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
			MPK[4][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
			MPK[5][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
			MPK[6][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
			MPK[7][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
			MPK[8][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
			MPK[9][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
			MPK[10][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		}
		MPK[11][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		MPK[11][1] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		MPK[12][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		MPK[12][1] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt].getBytes())); cnt++;
		return;
	}
	
	public void read_ABE_parameters(String filePath) throws IOException {
		FileReader fr = new FileReader(filePath);
    	BufferedReader br = new BufferedReader(fr);
    	MPK[0][0] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MPK[1][0] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MPK[2][0] = gt.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		for(int i=0; i<n; i++) {
			MPK[3][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MPK[4][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MPK[5][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MPK[6][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MPK[7][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MPK[8][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MPK[9][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MPK[10][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		}
		MPK[11][0] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MPK[11][1] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MPK[12][0] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MPK[12][1] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		br.close();
		fr.close();
	}
	
	public String Request_SK(String URL, String userAttribute) {
		HttpPost httpPost = new HttpPost(URL);
		HttpClient httpClient = new DefaultHttpClient();
		try {
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
            nameValuePairs.add(new BasicNameValuePair("msg","SK," + userAttribute));
            httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            // Response
            HttpResponse UPS_response = httpClient.execute(httpPost);
            // SK string format
            final String SK_string = EntityUtils.toString(UPS_response.getEntity());
            return SK_string;
		}
		catch(Exception e) {
			System.out.println("MPK request failed.");
		}
		return null;
	}

	public void write_SK_string_to_file(String SK_s, String filePath) throws IOException {
		String[] data = SK_s.split("#");
		FileWriter out = new FileWriter(filePath, true);
		for(int i=0; i<data.length; i++) {
			out.write(data[i]);out.write(newline_symbol);
		}
		out.close();
	}
	
	public void convert_SK_string_to_Element(String SK_s) {
		String[] data = SK_s.split("#");
		int cnt = 0;
		SK[0][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt++].getBytes()));
		SK[1][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt++].getBytes()));
		for(int i=0; i<n; i++) {
			SK[2][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt++].getBytes()));
			SK[3][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt++].getBytes()));
			SK[4][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt++].getBytes()));
			SK[5][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[cnt++].getBytes()));
		}
	}
	
	public void read_SK_parameters(String filePath) throws IOException {
		FileReader fr = new FileReader(filePath);
    	BufferedReader br = new BufferedReader(fr);
    	SK[0][0] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine().getBytes())).getImmutable();
    	SK[1][0] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine().getBytes())).getImmutable();
    	for(int i=0; i<n; i++) {
    		SK[2][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine().getBytes())).getImmutable();
    		SK[3][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine().getBytes())).getImmutable();
    		SK[4][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine().getBytes())).getImmutable();
    		SK[5][i] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine().getBytes())).getImmutable();
    	}
	}

	public String Hash(String input) throws GeneralSecurityException {
		MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
		messageDigest.update(input.getBytes());
		return new String(messageDigest.digest());
	}

	public String convert_CT_to_string(Element[][] CT) {
		// Convert attribute key to string (Base64, devided by '#')
		// With UV.Token
		String CT_s = "";
		CT_s += Base64.getEncoder().encodeToString(CT[0][0].toBytes()); CT_s += "#";
		CT_s += Base64.getEncoder().encodeToString(CT[1][0].toBytes()); CT_s += "#";
		for(int i=0; i<n; i++) {
			CT_s += Base64.getEncoder().encodeToString(CT[2][i].toBytes()); CT_s += "#";
			CT_s += Base64.getEncoder().encodeToString(CT[3][i].toBytes()); CT_s += "#";
			CT_s += Base64.getEncoder().encodeToString(CT[4][i].toBytes()); CT_s += "#";
			CT_s += Base64.getEncoder().encodeToString(CT[5][i].toBytes()); CT_s += "#";
		}
		CT_s += Base64.getEncoder().encodeToString(CT[6][0].toBytes()); CT_s += "#";
		CT_s += Base64.getEncoder().encodeToString(CT[7][0].toBytes()); CT_s += "#";
		CT_s += Base64.getEncoder().encodeToString(CT[7][1].toBytes());
		return CT_s;
	}

	public String send_CT(String URL, String CT, String hash_m) {
		HttpPost httpPost = new HttpPost(URL);
		HttpClient httpClient = new DefaultHttpClient();
		try {
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
            nameValuePairs.add(new BasicNameValuePair("msg","CT," + CT + "," + hash_m));
            httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            // Response
            HttpResponse UPS_response = httpClient.execute(httpPost);
            // event_number + OSVReqToken
            final String responseBody = EntityUtils.toString(UPS_response.getEntity());
            return responseBody;
		}
		catch(Exception e) {
			System.out.println("Send CT failed.");
		}
		return null;
	}

	public String send_OSVRespToken(String URL, String event_number, String OSVRespToken) {
		HttpPost httpPost = new HttpPost(URL);
		HttpClient httpClient = new DefaultHttpClient();
		try {
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
            nameValuePairs.add(new BasicNameValuePair("msg","OSVRespToken," + event_number + "," + OSVRespToken));
            httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            // Response
            HttpResponse UPS_response = httpClient.execute(httpPost);
            // AVReqToken
            final String responseBody = EntityUtils.toString(UPS_response.getEntity());
            return responseBody;
		}
		catch(Exception e) {
			System.out.println("Send OSVRespToken failed.");
		}
		return null;
	}
	
	public String send_AVRespToken(String URL, String event_number, String AVRespToken) {
		HttpPost httpPost = new HttpPost(URL);
		HttpClient httpClient = new DefaultHttpClient();
		try {
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
            nameValuePairs.add(new BasicNameValuePair("msg","AVRespToken," + event_number + "," + AVRespToken));
            httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            // Response
            HttpResponse UPS_response = httpClient.execute(httpPost);
            // Response message
            final String responseBody = EntityUtils.toString(UPS_response.getEntity());
            return responseBody;
		}
		catch(Exception e) {
			System.out.println("Send OSVRespToken failed.");
		}
		return null;
	}

	public String send_looking_for_pairing(String URL) {
		String req = "Looking for pairing request";
		HttpPost httpPost = new HttpPost(URL);
		HttpClient httpClient = new DefaultHttpClient();
		try {
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
            nameValuePairs.add(new BasicNameValuePair("msg", req));
            httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            // Response
            HttpResponse UPS_response = httpClient.execute(httpPost);
            // Response message (somebody's CT)
            final String responseBody = EntityUtils.toString(UPS_response.getEntity());
            return responseBody;
		}
		catch(Exception e) {
			System.out.println("Currently no pairing request.");
		}
		return null;
	}

	public String send_decryption_result(String URL, String event_number, String hash_M_prime) {
		String req = "Decryption result";
		HttpPost httpPost = new HttpPost(URL);
		HttpClient httpClient = new DefaultHttpClient();
		try {
            List<NameValuePair> nameValuePairs = new ArrayList<NameValuePair>();
            nameValuePairs.add(new BasicNameValuePair("msg", req + "," + event_number + "," + hash_M_prime));
            httpPost.setEntity(new UrlEncodedFormEntity(nameValuePairs));
            // Response
            HttpResponse UPS_response = httpClient.execute(httpPost);
            // Response message (Wrong or correct decryption result)
            final String responseBody = EntityUtils.toString(UPS_response.getEntity());
            return responseBody;
		}
		catch(Exception e) {
			System.out.println("Currently no pairing request.");
		}
		return null;
	}
}
