package com.servlet;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

// 

/**
 * Servlet implementation class UPS
 */
@WebServlet("/UPS")
public class UPS extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String filePath = "D:\\Java\\User_pairing_server\\User_pairing_server\\src\\main\\resources\\curves\\a.properties";
	final private static String ABE_parameters_filePath = "D:\\Java\\ABE_parameters.txt";
	final private static String SQL_record_filePath = "D:\\Java\\SQL_record.txt";
	private static Pairing pairing;
	public static Connection conn;
	// Need to delete and re-setup ABE_parameters.txt if n is changed.
	public static int max_wildcards = 7;
	private static int n = max_wildcards + 3;
	private final static int upper_bound = 10;
	private static int current_cnt = 0;
	private static int sql_pointer;
	private static Server_function_API API;
	private static long startTime;
    /**
     * @see HttpServlet#HttpServlet()
     */
    public UPS() {
        super();
        // TODO Auto-generated constructor stub
    }
    
    public void init() throws ServletException{
    	
    	// API
        pairing = PairingFactory.getPairing(filePath);
        try {
			API = new Server_function_API(max_wildcards, filePath);
		} catch (Exception e) {
			System.out.println("API initialization failed.");
			e.printStackTrace();
		}
        
        // Read file to check whether ABE parameters exist, if not, generate and write file.
        try {
	        File ABE_parameters = new File("D:\\Java\\ABE_parameters.txt");
	        if(!ABE_parameters.exists()) {// Haven't setup. Call Setup() and write parameters to file.
	        	System.out.println("File not found.");
	        	ABE_parameters.createNewFile();
	        	API.Setup();
	        	API.Write_ABE_parameters(API.MPK, API.MSK, ABE_parameters_filePath);
	        	System.out.println("ABE parameters file initialization finished.");
	        }
	        else {// Have setup before. Read file and get parameters.
	        	System.out.println("File found.");
				API.Read_ABE_parameters(ABE_parameters_filePath);
	        	System.out.println("ABE parameters file initialization finished.");
	        }
        } catch (Exception e) {
        	System.out.println("ABE parameters initialization failed.");
        	e.printStackTrace();
        }
        
        // MySQL
        try {
        	conn = API.SQL_connection();
        	System.out.println("Connect to MySQL database.");
        } catch (Exception e) {
        	System.out.println("MySQL initialization failed.");
        }
        
        FileReader fr;
		try {
			fr = new FileReader(SQL_record_filePath);
			BufferedReader br = new BufferedReader(fr);
			sql_pointer = Integer.parseInt(br.readLine());
		} catch (NumberFormatException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
        System.out.println("Server initialization finished.");
    }

	public static void processdata(String Data, HttpServletResponse response) throws Exception {
		String[] data = Data.split(",");
		// data[0] = DESCRIPTION
		if(data[0].equals("MPK")) {
			System.out.println("Receive MPK request!");
			startTime = System.currentTimeMillis();
			response.getOutputStream().write(API.generate_MPK_string(API.MPK).getBytes());
			System.out.println("MPK distribution time cost (server): " + (System.currentTimeMillis() - startTime) + "ms");
		}
		else if(data[0].equals("SK")) {
			// data[1] = attribute
			System.out.println("Receive SK request!");
			startTime = System.currentTimeMillis();
			// generate attribute array
			BigInteger[] attribute = new BigInteger[n];
			for(int i = 0; i<data[1].length(); i++) {
				if(data[1].charAt(i)=='0') {
					attribute[i] = BigInteger.ZERO;
				}
				else if(data[1].charAt(i)=='1') {
					attribute[i] = BigInteger.ONE;
				}
				else {
					System.out.println("Wrong attribute format!!");
					response.getOutputStream().write("Wrong attribute format!!".getBytes());
					return;
				}
			}
			
			// KeyGen
			Element[][] sk = API.KeyGen(API.MSK, attribute);
			
			// convert attribute key to string
			String sk_s = API.convert_sk_to_string(sk);
			
			response.getOutputStream().write(sk_s.getBytes());
			System.out.println("Attribute key generation time cost (server): " + (System.currentTimeMillis() - startTime) + "ms");
		}
		else if(data[0].equals("CT")) {
			System.out.println("Receive CT request!");
			startTime = System.currentTimeMillis();
			// User sends CT, response with OSVReqToken
			// data[1] = CT (devided by #, contains UVToken)
			// data[2] = hash(m)
			
			//generates challenge numbers and POST to the database
			Field zr = pairing.getZr();
			
			Element event_number = zr.newRandomElement().getImmutable();
			Element pi = zr.newRandomElement().getImmutable();
			Element sigma = zr.newRandomElement().getImmutable();
			Element rho = zr.newRandomElement().getImmutable();
			
			String event_number_s = Base64.getEncoder().encodeToString(event_number.toBytes());
			String pi_s = Base64.getEncoder().encodeToString(pi.toBytes());
			String sigma_s = Base64.getEncoder().encodeToString(sigma.toBytes());
			String rho_s = Base64.getEncoder().encodeToString(rho.toBytes());
			
			// Post: event_nummber(0), challenge1_pi(1), challenge2_sigma(2), challenge2_rho(3), hash_m(4), CT(5)
			String[] parts = new String[7];
			parts[0] = event_number_s;
			parts[1] = pi_s;
			parts[2] = sigma_s;
			parts[3] = rho_s;
			parts[4] = data[2]; //hash_m
			parts[5] = data[1]; //CT
					
			API.Post(conn, parts);
				
			Element[][] CT = API.Get_CT_from_string(data[1]);
			
			//generates ownership verification token
			Element token = API.OwnershipVerReqTokenGen(API.MPK, pi, CT);
			String OSVReqToken_s = Base64.getEncoder().encodeToString(token.toBytes());
			String response_message = event_number_s + "," + OSVReqToken_s;
			
			response.getOutputStream().write(response_message.getBytes());
			System.out.println("Ownership verification token generation time cost (server): " + (System.currentTimeMillis() - startTime) + "ms");
		}
		else if(data[0].equals("OSVRespToken")) {
			System.out.println("Receive OSVRespToken request!");
			startTime = System.currentTimeMillis();
			// data[1] = event number
			// data[2] = OSVRespToken
			
			// get parameters (challenges)
			String query = API.query_challenge_by_eventnumber(conn, data[1]);
			
			// challenges[0] = pi
			// challenges[1] = sigma
			// challenges[2] = rho
			String[] challenges = query.split(",");
			
			// Convert challenge1 (pi) to Element type
			Element pi = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(challenges[0])).getImmutable();
			
			// Get CT by event number and convert it to Element type
			String CT_s = API.query_CT_by_eventnumber(conn, data[1]);
			Element[][] CT = API.Get_CT_from_string(CT_s);
			
			// Convert OSVRespToken to Element type
			Element OSVRespToken = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(data[2]));
			if(API.OwnershipVer(CT, pi, OSVRespToken)==true) {
				long tmp_time = System.currentTimeMillis();
				System.out.println("Ownership verification time cost (server): " + (tmp_time - startTime) + "ms");
				// Ownership verification passed, generate AVReqToken.
				
				// Convert sigma, rho to Element type
				Element sigma = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(challenges[1]));
				Element rho = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(challenges[2]));
				Element[][] AVReqToken = API.AttributeVerReqTokenGen(CT, sigma, rho);
				String AVReqToken_s = API.convert_AVReqToken_to_string(AVReqToken);
				response.getOutputStream().write(AVReqToken_s.getBytes());
				System.out.println("Attribute verification token generation time cost (server): " + (System.currentTimeMillis() - tmp_time) + "ms");
			}
			else {
				response.getOutputStream().write("Ownership verification failed.".getBytes());
			}
		}
		else if(data[0].equals("AVRespToken")) {
			System.out.println("Receive AVRespToken request!");
			startTime = System.currentTimeMillis();
			// data[1] = event number
			// data[2] = AVRespToken (two values, devided by #)
			
			// Get challenge numbers from database
			String query = API.query_challenge_by_eventnumber(conn, data[1]);
			
			// challenges[0] = challenge1_pi
			// challenges[1] = challenge2_sigma
			// challenges[2] = challenge2_rho
			String[] challenges = query.split(",");
			
			// Convert sigma, rho to Element type
			Element sigma = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(challenges[1]));
			Element rho = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(challenges[2]));
			
			// Get CT from database
			String CT_s = API.query_CT_by_eventnumber(conn, data[1]);
			Element[][] CT = API.Get_CT_from_string(CT_s);// UV.Token: CT[7][0], CT[7][1]
			
			// Get AVRespToken
			Element[] AVRespToken = new Element[2];
			String[] AVRespToken_string = data[2].split("#");
			AVRespToken[0] = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(AVRespToken_string[0]));
			AVRespToken[1] = pairing.getGT().newElementFromBytes(Base64.getDecoder().decode(AVRespToken_string[1]));
			if(API.AttributeVer(AVRespToken, CT, sigma, rho, API.MPK) == true) {
				// Remove UVToken before sending CT to other users
				CT[7][0] = null;
				CT[7][1] = null;
				System.out.println("Sending request..., event number: " + data[1]);
				API.update_available_CT(conn, data[1], CT);
				response.getOutputStream().write("User legitimacy verification passed.".getBytes());
				System.out.println("Attribute verification time cost (server): " + (System.currentTimeMillis() - startTime) + "ms");
			}
			else {
				System.out.println("User legitimacy verification failed. Beyond-authority request!!!");
				response.getOutputStream().write("User legitimacy verification failed.".getBytes());
			}
		}
		else if(data[0].equals("Decryption result")) {
			System.out.println("Receive Decryption_result request!");
			startTime = System.currentTimeMillis();
			// data[1] = event number
			// data[2] = hash(m)
			String QUERY = "SELECT hash_m FROM user_pairing_server.parameters WHERE eventnumber =\"" + data[1] + "\"";
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(QUERY);
			String hash_m = "";
			if(rs.next()) {// if success
				hash_m = rs.getString("hash_m");
				System.out.println("Query Finished.");
				if(data[2].equals(hash_m)) {
	    			response.getOutputStream().write("Correct decryption result".getBytes());
	    			System.out.println("Legitimate responder join.");
					System.out.println("Decryption result verification time cost (server): " + (System.currentTimeMillis() - startTime) + "ms");
	    		}
				else {
					response.getOutputStream().write("Wrong decryption result".getBytes());
				}
			}
			else {
				response.getOutputStream().write("No such event".getBytes());
			}
		}
		else if(data[0].equals("Looking for pairing request")) {
			System.out.println("Someone is looking for pairing...");
			startTime = System.currentTimeMillis();
			if(current_cnt == upper_bound) {
				// Delete such pairing request and update current available pairing request
				current_cnt = 0;
				String QUERY = "DELETE FROM user_pairing_server.hash_message WHERE id=\"" + sql_pointer + "\"";
				sql_pointer++;
				
				// Re-write current pairing request number to file
				File file = new File(SQL_record_filePath);
				FileWriter fw = new FileWriter(file, false);
				fw.write(sql_pointer);
				fw.close();
			}
			else {
				current_cnt++;
			}
			String QUERY = "SELECT eventnumber, CT FROM user_pairing_server.hash_message WHERE id=\"" + sql_pointer + "\"";
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(QUERY);
			String event_number = "", CT = "";
			if(rs.next()) {// if success
				event_number = rs.getString("eventnumber");
				CT = rs.getString("CT");
				response.getOutputStream().write((event_number + "," + CT).getBytes());
				System.out.println("Pairing request distribution time cost (server): " + (System.currentTimeMillis() - startTime) + "ms");
			}
			else {
				System.out.println("Currently no pairing request.");
				response.getOutputStream().write("Currently no pairing request.".getBytes());
			}
		}
		else {
			response.getOutputStream().write("Wrong format.".getBytes());
		}
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		doPost(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		if(!request.getParameter("msg").equals(null)) {
			String Data = request.getParameter("msg");
			try {
				processdata(Data, response);
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		else {
			response.getOutputStream().write("Wrong request format".getBytes());
		}
	}

}
