package com.upue;

import java.io.File;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class UPUE {
	public static String URL = "http://140.117.172.197:8080/UPS/";
	public int max_wildcards = 7;
	public int n = max_wildcards + 3;
	public static String pairing_filePath = "D:\\Java\\User_pairing_server\\User_pairing_server\\src\\main\\resources\\curves\\a.properties";
	public String MPK_filePath = "D:\\Java\\User_MPK_parameters.txt";
	public String SK_filePath = "D:\\Java\\User_SK_parameters.txt";
	Element[][] MPK;
	public static Pairing pairing = PairingFactory.getPairing(pairing_filePath);
	public static UE_function_API API;

	public int[] policy = {1,1,1,0,0,0,0,0,0,0};
	public String userAttribute = "1110000000";
	
	// Constructor - init
	public UPUE() throws Exception{
		API = new UE_function_API(max_wildcards);
		// read file (MPK & SK), if not exist then request and write file
		// MPK
		File MPK_parameters = new File(MPK_filePath);
		if(!MPK_parameters.exists()) {
			System.out.println("MPK file not found.");
			
			// Request MPK
			String MPK_s = API.Request_MPK(URL);
			
			// Write file
			MPK_parameters.createNewFile();
			API.write_MPK_string_to_file(MPK_s, MPK_filePath);
			
			// Convert MPK to Element format
			API.convert_MPK_string_to_Element(MPK_s);
		}
		else {
			System.out.println("MPK file found.");
			
			// Read and load MPK - Element format
			API.read_ABE_parameters(MPK_filePath);
		}
		System.out.println("MPK init finished.");
		
		// SK
		File SK_parameters = new File(SK_filePath);
		if(!SK_parameters.exists()) {
			System.out.println("SK file not found.");
			
			// Request SK
			String SK_s = API.Request_SK(URL, userAttribute);
			
			// Write SK to file
			API.write_SK_string_to_file(SK_s, SK_filePath);
			
			// Convert SK to Element format
			API.convert_SK_string_to_Element(SK_s);
		}
		else {
			System.out.println("SK file found");
			
			// Read and load SK - Element format
			API.read_SK_parameters(SK_filePath);
		}
		System.out.println("SK init finished.");
	}
	
	public static void main(String args[]) throws Exception {
		UPUE upue = new UPUE();
		
		// Generate and send CT, then get OSVReqToken as response
		String response = upue.send_CT();
		String[] CT_resp = response.split(","); // CT_resp[0]: event number, CT_resp[1]: OSVReqToken
		
		// Generate and send OSVRespToken, then get AVReqToken (with event_number) as response
		response = upue.send_OSVRespToken(CT_resp[0], CT_resp[1]);
		String[] AV_resp = response.split(","); // AV_resp[0]: event_number, AV_resp[1]: AVReqToken (String format, concated by #)
		
		// Generate and send AVRespToken
		upue.send_AVRespToken(AV_resp[0], AV_resp[1]);
		
		// Looking for pairing request
		response = API.send_looking_for_pairing(URL);
		if(!response.equals("Currently no pairing request.")) {
			String[] CT_req = response.split(","); // CT_req[0]: event_number, CT_req[1]: CT (devided by #);
			Element decryption_result = API.decrypt(CT_req[1]);
			String hash_m_prime = API.Hash(Base64.getEncoder().encodeToString(decryption_result.toBytes()));
			response = API.send_decryption_result(URL, CT_req[0], hash_m_prime);
		}
		else {
			System.out.println("Currently no pairing request.");
		}
		
	}
	
	public String send_CT() throws Exception {
		Element M = pairing.getGT().newRandomElement().getImmutable();
		Element[][] CT = API.generate_CT(policy, M);
		// Convert to hash(m) and CT_string with UV.Token
		String hash_m = API.Hash(Base64.getEncoder().encodeToString(M.toBytes()));
		String CT_s = API.convert_CT_to_string(CT);
		String responseBody = API.send_CT(URL, CT_s, hash_m);
		// Return event_number + OSVReqToken
		return responseBody;
	}
	
	public String send_OSVRespToken(String event_number, String OSVReqToken) {
		Element OSVRespToken = API.get_OSVRespToken(OSVReqToken);
		String OSVRespToken_s = Base64.getEncoder().encodeToString(OSVRespToken.toBytes());
		String responseBody = API.send_OSVRespToken(URL, event_number, OSVRespToken_s);
		return event_number + "," + responseBody;
	}
	
	public void send_AVRespToken(String event_number, String AVReqToken) throws Exception {
		Element[] AVRespToken = API.get_AVRespToken(AVReqToken);
		String AVRespToken_s = "";
		AVRespToken_s += Base64.getEncoder().encodeToString(AVRespToken[0].toBytes());
		AVRespToken_s += "#";
		AVRespToken_s += Base64.getEncoder().encodeToString(AVRespToken[1].toBytes());
		String responseBody = API.send_AVRespToken(URL, event_number, AVRespToken_s);
		System.out.println(responseBody);
	}
}
