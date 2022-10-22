package com.servlet;
import crypto.ABE_server;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.Scanner;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


public class Server_function_API{
	
	// For ABE
	public static int max_wildcards;
	//public static Pairing pairing;
	private static int n = max_wildcards + 3;
	public Element MPK[][];
	public Element MSK[][];
	public Field zr;
	public Field g1;
	public Field gt;

	final private static String newline_symbol = "\n";
	private static String filePath = "D:\\Java\\User_pairing_server\\User_pairing_server\\src\\main\\resources\\curves\\a.properties";
	final private Pairing pairing = PairingFactory.getPairing(filePath);
	
	// For TLS
	private static Map<String, String> user_value = new HashMap<>();
	public static KeyFactory keyFactory;
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	final private static String ip = "140.117.172.197";//Server's ip
	final private static String keystorePath = "C:\\Users\\±i¦u¤¤\\keystore\\";
	public PublicKey cloud_server_pk;//cloud server's public key
	public KeyPair getKeyPair(KeyFactory keyFactory) throws Exception {
		
		byte[] publicKeyData = Files.readAllBytes(Paths.get(keystorePath + ip +".pubkey.der"));//app server pk file path
		byte[] privateKeyData = Files.readAllBytes(Paths.get(keystorePath + ip +".prikey.der"));//app server sk file path
		
		X509EncodedKeySpec publicKeySpec= new X509EncodedKeySpec(publicKeyData);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
		
		publicKey = keyFactory.generatePublic(publicKeySpec);
		privateKey = keyFactory.generatePrivate(privateKeySpec);
		
		return new KeyPair(publicKey, privateKey);
	}
	
	/*public static void main(String[] args) throws Exception {
		Server_function_API api = new Server_function_API();
	}*/
	
	// Constructor
	ABE_server ABE;
	public Server_function_API(int wildcard_number, String curve_path) throws Exception {
		Server_function_API.max_wildcards = wildcard_number;
		n = max_wildcards + 3;
		
		ABE = new ABE_server(max_wildcards, curve_path);
		this.MPK = new Element[13][n];
		this.MSK = new Element[11][n];
		this.zr = ABE.zr;
		this.g1 = ABE.g1;
		this.gt = ABE.gt;
		byte[] publicKeyData = Files.readAllBytes(Paths.get(keystorePath + "cs_pubkey.der"));
        X509EncodedKeySpec publicKeySpec= new X509EncodedKeySpec(publicKeyData);
        keyFactory = KeyFactory.getInstance("RSA");
        cloud_server_pk = keyFactory.generatePublic(publicKeySpec);
		System.out.println("API init finished.");
	}
	
	public void Setup() throws Exception {
		System.out.println("API setup.");
		ABE.setup();
		MPK = ABE.MPK;
		MSK = ABE.MSK;
	}
	
	public Element[][] KeyGen(Element[][] MSK, BigInteger[] attribute) throws Exception{
		if(attribute.length != n) {
			System.out.println("WRONG ATTRIBUTE SIZE!!");
			System.out.println("The attribute size is:" + attribute.length + ", expected: " + n);
			return null;
		}
		return ABE.KeyGen(MSK, attribute);
	}
	
	public Element OwnershipVerReqTokenGen(Element[][] MPK, Element pi, Element[][]CT) {
		return ABE.OwnershipVerReqTokenGen(MPK, pi, CT);
	}
	
	public boolean OwnershipVer(Element[][] CT, Element challenge_1, Element OVRespToken) {
		return ABE.OwnershipVer(CT, challenge_1, OVRespToken);
	}
	
	public Element[][] AttributeVerReqTokenGen(Element[][] CT, Element sigma, Element rho){
		return ABE.AttributeVerReqTokenGen(CT, sigma, rho);
	}
	
	public boolean AttributeVer(Element[] AVRespToken, Element[][] CT, Element sigma, Element rho, Element[][] MPK) {
		return ABE.AttributeVer(AVRespToken, CT, sigma, rho, MPK);
	}
	
	public void Read_ABE_parameters(String ABE_parameters_filepath) throws Exception {
    	FileReader fr = new FileReader(ABE_parameters_filepath);
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
		
		MSK[0][0] = g1.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		for(int i=0; i<n; i++) {
			MSK[1][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MSK[2][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MSK[3][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MSK[4][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MSK[5][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MSK[6][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MSK[7][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
			MSK[8][i] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		}
		MSK[9][0] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MSK[9][1] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MSK[10][0] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		MSK[10][1] = zr.newElementFromBytes(Base64.getDecoder().decode(br.readLine())).getImmutable();
		br.close();
		fr.close();
	}
	
	public Element[][] Get_CT_from_string(String CT_string) {
		String[] CT_s = CT_string.split("#");
		
		// Converts CT back to Element type
		Element[][] CT = new Element[8][n];
		int cnt = 0;
		
		//CA,CB
		CT[0][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;//CA
		CT[1][0] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;//CB
		
		//C{1,i} ~ C{4,i}
		for(int i=0; i<n; i++) {
			CT[2][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;
			CT[3][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;
			CT[4][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;
			CT[5][i] = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;
		}
		//Cm
		CT[6][0] = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;
		
		//UV.Token
		CT[7][0] = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;//Cm^tau
		CT[7][1] = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(CT_s[cnt]));cnt++;//s2*tau
		return CT;
	}
	
	public void Write_ABE_parameters(Element[][] MPK, Element[][] MSK, String ABE_parameters_filepath) throws Exception {
		FileWriter out = new FileWriter(ABE_parameters_filepath, true);
		//MPK
    	out.write(Base64.getEncoder().encodeToString(MPK[0][0].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MPK[1][0].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MPK[2][0].toBytes()));out.write(newline_symbol);
    	for(int i=0; i<n; i++) {
    		out.write(Base64.getEncoder().encodeToString(MPK[3][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MPK[4][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MPK[5][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MPK[6][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MPK[7][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MPK[8][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MPK[9][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MPK[10][i].toBytes()));out.write(newline_symbol);
    	}
    	out.write(Base64.getEncoder().encodeToString(MPK[11][0].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MPK[11][1].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MPK[12][0].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MPK[12][1].toBytes()));out.write(newline_symbol);
    	
    	//MSK
    	out.write(Base64.getEncoder().encodeToString(MSK[0][0].toBytes()));out.write(newline_symbol);
    	for(int i=0; i<n; i++) {
    		out.write(Base64.getEncoder().encodeToString(MSK[1][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MSK[2][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MSK[3][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MSK[4][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MSK[5][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MSK[6][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MSK[7][i].toBytes()));out.write(newline_symbol);
    		out.write(Base64.getEncoder().encodeToString(MSK[8][i].toBytes()));out.write(newline_symbol);
    	}
    	out.write(Base64.getEncoder().encodeToString(MSK[9][0].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MSK[9][1].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MSK[10][0].toBytes()));out.write(newline_symbol);
    	out.write(Base64.getEncoder().encodeToString(MSK[10][1].toBytes()));out.write(newline_symbol);
    	out.flush();
    	out.close();
	}
	
	public boolean signature_verify(PublicKey pk, String data, byte[] signature) {
		try {
			//long verStartTime = System.currentTimeMillis();
			Signature sign = Signature.getInstance("SHA256withRSA");
			byte[] bytes = data.getBytes();
			sign.initVerify(pk);
			sign.update(bytes);
			//long verStopTime = System.currentTimeMillis();
			//System.out.println("Signature Verify Time: " + Long.toString(verStopTime - verStartTime) + "ms");
			return sign.verify(signature);
		}
		catch (Exception e) {e.printStackTrace();}
		return false;
	}
	
	private String mutual_authentication(String ppk, String r_a) {//return string(r_b, sig(a||b))
		try {
			SecureRandom sr = new SecureRandom();
			Long r_b = sr.nextLong();
			user_value.put(ppk, String.valueOf(r_b));
			String data = r_a + "," + r_b.toString();
			byte[] sign = signature_gen(data);
			return r_b.toString() + "," + sign.toString();
		}catch(Exception e) {
			System.out.println("Mutual Authentication Failed.");
		}
		return null;
	}
	
	public byte[] signature_gen(String data) {
		try {		
			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(privateKey);
			byte[] bytes = data.getBytes();
			sign.update(bytes);
			return sign.sign();
		}
		catch (Exception e) {System.out.println("Sig-gen failed");}
		return null;
	}

	public PublicKey get_user_pk(String input) throws Exception {
		byte[] publicKey = Base64.getDecoder().decode(input);
		X509EncodedKeySpec user_pk_spec = new X509EncodedKeySpec(publicKey);
		PublicKey user_pk = keyFactory.generatePublic(user_pk_spec);
		return user_pk;
	}
	
	// MySQL
	public Connection SQL_connection() throws Exception {//basic connects to MySQL database
		try {
			String driver = "com.mysql.cj.jdbc.Driver";
			String url = "jdbc:mysql://localhost:3306/";
			String username = "root";
			String password = "1234";
			Class.forName(driver);
			Connection conn = DriverManager.getConnection(url, username, password);
			System.out.println("Connected.");
			return conn;
		}catch(Exception e) {System.out.println(e);}
		
		return null;
	}
	
	public void Post(Connection conn, String[] data) throws Exception {
		// Format: event_number(0), challenge1_pi(1), challenge2_sigma(2), challenge2_rho(3), hash_m(4), CT(5), UV.token(6), Time
		
		String SQL_path = "user_pairing_server.parameters";
		SimpleDateFormat dfDate  = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date currentTime = new Date(System.currentTimeMillis());
		PreparedStatement check_data_exists = conn.prepareStatement("SELECT eventnumber from user_pairing_server.parameters WHERE eventnumber=\""+ data[0] +"\"");
		ResultSet rs = check_data_exists.executeQuery();
		String event_number_s = "";
		if(!rs.next()) {// No data found
			PreparedStatement preparedPosted = conn.prepareStatement("INSERT INTO " + SQL_path + "(eventnumber, pi, sigma, rho, hash_m, CT, time) VALUES" + "('" + 
					data[0] + "','" + data[1] + "','" + data[2] + "','" + data[3] + "','" + data[4] + "','" + data[5] + "','" + dfDate.format(currentTime) + "');");
			System.out.println(data[0]);
			preparedPosted.execute();
			System.out.println("User Data posted at time: " + dfDate.format(currentTime));
		}
		else {// Such event number already exists
			while(rs.next()) {
				Element event_number = zr.newRandomElement().getImmutable();
				event_number_s = Base64.getEncoder().encodeToString(event_number.toBytes());
				check_data_exists = conn.prepareStatement("SELECT eventnumber from user_pairing_server.parameters WHERE eventnumber=\""+ event_number_s +"\"");
				rs = check_data_exists.executeQuery();
			}
			rs.close();
			data[0] = event_number_s;
			PreparedStatement preparedPosted = conn.prepareStatement("INSERT INTO " + SQL_path + "(eventnumber, pi, sigma, rho, hash_m, CT, time) VALUES" + "('" + 
					data[0] + "','" + data[1] + "','" + data[2] + "','" + data[3] + "','" + data[4] + "','" + data[5] + "','" + dfDate.format(currentTime) + "');");
			preparedPosted.execute();
			System.out.println("User Data posted at time: " + dfDate.format(currentTime));
		}
		
	}
	
	public String query_challenge_by_eventnumber(Connection conn, String event_number) throws Exception {
		try {
			String QUERY = "SELECT pi, sigma, rho FROM user_pairing_server.parameters WHERE eventnumber =\"" + event_number + "\"";
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(QUERY);
			if(rs.next()) {// if success
				String challenge1_pi = rs.getString("pi");
				String challenge2_sigma = rs.getString("sigma");
				String challenge2_rho = rs.getString("rho");
				//System.out.println("Query Finished.");
				return challenge1_pi + ","  + challenge2_sigma + "," + challenge2_rho;
			}
			else { return "Query Failed."; }
		}
		catch(Exception e) {
			e.printStackTrace();
			return "Query Failed.";
		}
	}
	
	public String query_CT_by_eventnumber(Connection conn, String event_number) throws Exception {
		try {
			String QUERY = "SELECT CT FROM user_pairing_server.parameters WHERE eventnumber =\"" + event_number + "\"";
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(QUERY);
			if(rs.next()) {// if success
				String CT = rs.getString("CT");
				//System.out.println("Query Finished.");
				return CT;
			}
			else { return "Query Failed."; }
		}
		catch(Exception e) {
			e.printStackTrace();
			return "Query Failed.";
		}
	}
	
	public String generate_MPK_string(Element[][] MPK) {
		String MPK_string = "";
		MPK_string += Base64.getEncoder().encodeToString(MPK[0][0].toBytes()); MPK_string += "#";
		MPK_string += Base64.getEncoder().encodeToString(MPK[1][0].toBytes()); MPK_string += "#";
		MPK_string += Base64.getEncoder().encodeToString(MPK[2][0].toBytes()); MPK_string += "#";
		for(int i=0; i<n; i++) {
			MPK_string += Base64.getEncoder().encodeToString(MPK[3][i].toBytes()); MPK_string += "#";
			MPK_string += Base64.getEncoder().encodeToString(MPK[4][i].toBytes()); MPK_string += "#";
			MPK_string += Base64.getEncoder().encodeToString(MPK[5][i].toBytes()); MPK_string += "#";
			MPK_string += Base64.getEncoder().encodeToString(MPK[6][i].toBytes()); MPK_string += "#";
			MPK_string += Base64.getEncoder().encodeToString(MPK[7][i].toBytes()); MPK_string += "#";
			MPK_string += Base64.getEncoder().encodeToString(MPK[8][i].toBytes()); MPK_string += "#";
			MPK_string += Base64.getEncoder().encodeToString(MPK[9][i].toBytes()); MPK_string += "#";
			MPK_string += Base64.getEncoder().encodeToString(MPK[10][i].toBytes()); MPK_string += "#";
		}
		MPK_string += Base64.getEncoder().encodeToString(MPK[11][0].toBytes()); MPK_string += "#";
		MPK_string += Base64.getEncoder().encodeToString(MPK[11][1].toBytes()); MPK_string += "#";
		MPK_string += Base64.getEncoder().encodeToString(MPK[12][0].toBytes()); MPK_string += "#";
		MPK_string += Base64.getEncoder().encodeToString(MPK[12][1].toBytes());
		return MPK_string;
	}
	
	public String convert_sk_to_string(Element[][] sk) {
		String sk_s = "";
		// Convert attribute key to string (Base64, devided by '#')
		sk_s += Base64.getEncoder().encodeToString(sk[0][0].toBytes()); sk_s += "#";
		sk_s += Base64.getEncoder().encodeToString(sk[1][0].toBytes()); sk_s += "#";
		for(int i=0; i<n; i++) {
			sk_s += Base64.getEncoder().encodeToString(sk[2][i].toBytes()); sk_s += "#";
			sk_s += Base64.getEncoder().encodeToString(sk[3][i].toBytes()); sk_s += "#";
			sk_s += Base64.getEncoder().encodeToString(sk[4][i].toBytes()); sk_s += "#";
			sk_s += Base64.getEncoder().encodeToString(sk[5][i].toBytes()); sk_s += "#";
		}
		return sk_s;
	}
	
	public String convert_AVReqToken_to_string(Element[][] AVReqToken) {
		String AVReqToken_s = "";
		AVReqToken_s += Base64.getEncoder().encodeToString(AVReqToken[0][0].toBytes()); AVReqToken_s +="#";
		AVReqToken_s += Base64.getEncoder().encodeToString(AVReqToken[1][0].toBytes()); AVReqToken_s +="#";
		for(int i=0; i<n; i++) {
			AVReqToken_s += Base64.getEncoder().encodeToString(AVReqToken[2][i].toBytes()); AVReqToken_s +="#";
			AVReqToken_s += Base64.getEncoder().encodeToString(AVReqToken[3][i].toBytes()); AVReqToken_s +="#";
			AVReqToken_s += Base64.getEncoder().encodeToString(AVReqToken[4][i].toBytes()); AVReqToken_s +="#";
			AVReqToken_s += Base64.getEncoder().encodeToString(AVReqToken[5][i].toBytes()); AVReqToken_s +="#";
		}
		AVReqToken_s += Base64.getEncoder().encodeToString(AVReqToken[6][0].toBytes());
		return AVReqToken_s;
	}
	
	public String convert_CT_to_string(Element[][] CT) {
		// Convert CT to string (Base64, devided by '#')
		// Without UV.Token
		String CT_s = "";
		CT_s += Base64.getEncoder().encodeToString(CT[0][0].toBytes()); CT_s += "#";
		CT_s += Base64.getEncoder().encodeToString(CT[1][0].toBytes()); CT_s += "#";
		for(int i=0; i<n; i++) {
			CT_s += Base64.getEncoder().encodeToString(CT[2][i].toBytes()); CT_s += "#";
			CT_s += Base64.getEncoder().encodeToString(CT[3][i].toBytes()); CT_s += "#";
			CT_s += Base64.getEncoder().encodeToString(CT[4][i].toBytes()); CT_s += "#";
			CT_s += Base64.getEncoder().encodeToString(CT[5][i].toBytes()); CT_s += "#";
		}
		CT_s += Base64.getEncoder().encodeToString(CT[6][0].toBytes());
		return CT_s;
	}
	
	public void update_available_CT(Connection conn, String event_number, Element[][] CT) throws SQLException {
		String QUERY = "SELECT hash_m FROM user_pairing_server.parameters WHERE eventnumber =\"" + event_number + "\"";
		Statement stmt = conn.createStatement();
		ResultSet rs = stmt.executeQuery(QUERY);
		String hash_m;
		if(rs.next()) {// if success
			hash_m = rs.getString("hash_m");
			//System.out.println("Query Finished.");
		}
		else {
			System.out.println("Query Failed.");
			return;
		}
		String CT_s = convert_CT_to_string(CT);
		SimpleDateFormat dfDate  = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Date currentTime = new Date(System.currentTimeMillis());
		String POST = "INSERT INTO user_pairing_server.hash_message (eventnumber, hash_m, CT, time) VALUES" + 
				" ('"+event_number+"','"+hash_m+"','"+CT_s+"','"+dfDate.format(currentTime)+"');";
		PreparedStatement preparedPosted = conn.prepareStatement(POST);
		preparedPosted.execute();
		System.out.println("Available hash_m, CT updated.");
	}
}