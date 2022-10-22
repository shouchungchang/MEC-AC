package com.servlet;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.tomcat.util.codec.binary.Base64;
import org.bouncycastle.util.encoders.Hex;

import it.unisa.dia.gas.jpbc.Pairing;

//import org.apache.commons.lang3.time.StopWatch;;
//user_profile = name + email + muid
//sql format : mUid ppk user_name email autho_level TTL

/**
 * Servlet implementation class App_Server
 */
@WebServlet("/App_Server")
public class App_Server extends HttpServlet{
	public static void main(String[] args) {
		try {
			//testbed
			System.out.println("Start.");
		}
		catch(Exception e) {}
	}
	
	private static Map<String, String> user_value = new HashMap<>();
	private static PublicKey cloud_server_pk;//cloud server's public key
	private static PublicKey publicKey;
	private static PrivateKey privateKey;
	public static KeyFactory keyFactory;
	final private static String ip = "140.117.172.197";//App Server's ip
	final private static String keystorePath = "C:\\Users\\張守中\\keystore\\";
	//private static Pairing pairing;
	
	public static KeyPair getKeyPair(KeyFactory keyFactory) throws Exception {
		
		byte[] publicKeyData = Files.readAllBytes(Paths.get(keystorePath + ip +".pubkey.der"));//app server pk file path
		byte[] privateKeyData = Files.readAllBytes(Paths.get(keystorePath + ip +".prikey.der"));//app server sk file path
		
		X509EncodedKeySpec publicKeySpec= new X509EncodedKeySpec(publicKeyData);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
		
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		
		return new KeyPair(publicKey, privateKey);
	}
	
	private static String mutual_authentication(String ppk, String r_a) {//return string(r_b, sig(a||b))
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
	
	public static void processdata(String Data, HttpServletResponse response) {
		try {
			String parts[] = Data.split(",");
			if(parts[0].equals("Service Data")) {
				//parameters : ppk(1), name(2), email(3), mUid(4), autho_level(5), sig(6)
				//stores data received from cloud server
				Connection conn = SQL_connection();
				Post(conn, parts[1], parts[2], parts[3], parts[4], parts[5]);
				conn.close();
			}
			else if(parts[0].equals("UAM Request")) {
				//	parameters : Sig-psk(data), ppk, Sig-cs(ppk)
				//1. Verifies ppk using Cloud Server Sign
				//2. Finds user data by ppk
				//3. Verfies Sig-psk(data) by found user data and r_b
				System.out.println("UAM Request start.");
				long UAM_time_start = System.currentTimeMillis();
				if(signature_verify(cloud_server_pk, parts[2], Hex.decode(parts[3]))) {
					Connection conn = SQL_connection();
					byte[] publicKey = Base64.decodeBase64(parts[2]);
					X509EncodedKeySpec user_pk_spec = new X509EncodedKeySpec(publicKey);
					PublicKey user_pk = keyFactory.generatePublic(user_pk_spec);
					String compare_string = new String(userdata_Query(conn, parts[2]) + "," + user_value.get(parts[2]));//ppk,user_profile,autho_level,r_b
					if(signature_verify(user_pk, compare_string , Hex.decode(parts[1]))) {
						//generates user's UAM
						Date TTL = new Date(System.currentTimeMillis() + 1000L * 60 * 60 * 24 * 15);//TTL : 15 days
						SimpleDateFormat dfDate  = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
						byte[] UAM = signature_gen(userdata_Query(conn, parts[2]) + "," + dfDate.format(TTL));//UAM
						byte[] sig_UAM = signature_gen(UAM.toString());
						System.out.println("UAM generation successful, expired at : " + dfDate.format(TTL));//到期日
						response.getOutputStream().write((Hex.toHexString(UAM) + "," + dfDate.format(TTL) + "," + Hex.toHexString(sig_UAM) + "," + ip).getBytes());
						
						long UAM_time_end = System.currentTimeMillis();
						long UAM_millis = UAM_time_end - UAM_time_start;
						System.out.println("UAM-gen total time: " + UAM_millis);
					}
					else {
						System.out.println("User's signature not correct");
					}
				}
				else {response.getOutputStream().write(("UAM Request rejected.").getBytes());}
			}
			else if(parts[0].equals("Fast Login")) {
				// parameters : ppk(1), TTL(2), 〖𝑆𝑖𝑔〗_(〖𝑠𝑘〗_𝐶𝑆 )(P-PK)(3), UAM(4), 〖𝑆𝑖𝑔〗_(𝑃−𝑆𝐾)( UAM, 𝑟_𝑏)(5)
				//1. App Server check P-PK by 〖𝑆𝑖𝑔〗_(〖𝑠𝑘〗_𝐶𝑆 )(P-PK) and 〖𝑝𝑘〗_𝐶𝑆 
				//2. Use P-PK to compare 〖𝑆𝑖𝑔〗_(𝑃−𝑆𝐾)( UAM, 𝑟_𝑏)  and UAM with 𝑟_𝑏  
				//3. Find Autho. Set and User Profile using P-PK from its database
				//4. App Server using P-PK, User Profile, Autho. Set,  TTL and its own 〖𝑝𝑘〗_𝑆𝐴𝑆  to verify UAM
				long fl_time_start = System.currentTimeMillis();
				Connection conn = SQL_connection();
				String Query = "SELECT ppk FROM app_server_userdata.app_userdata WHERE ppk=\"" + parts[1] + "\"";
				Statement stmt = conn.createStatement();
				ResultSet rs = stmt.executeQuery(Query);
				if(rs.next()) {//if exists
					if(signature_verify(cloud_server_pk, parts[1], Hex.decode(parts[3]))) {//step 1
						byte[] user_publicKey = Base64.decodeBase64(parts[1]);
						X509EncodedKeySpec user_pk_spec= new X509EncodedKeySpec(user_publicKey);
						PublicKey user_pk = keyFactory.generatePublic(user_pk_spec);
						if(signature_verify(user_pk, parts[4] + "," + user_value.get(parts[1]), Hex.decode(parts[5]))) {//step 2
							String compare_data = userdata_Query(conn, parts[1]); // step 3 -> (ppk, user profile, autho level.) + TTL
							//may have some problems, not sure which returns query failed or null value - 0827
							if(!compare_data.equals("Query Failed.")) {
								compare_data = compare_data + "," + parts[2];
								if(signature_verify(publicKey, compare_data, Hex.decode(parts[4]))) {//step 4
									System.out.println("Fast Login succeed.");
									response.getOutputStream().write(("Authentication Succeed - Fast Login Succeed.").getBytes());
									long fl_time_end = System.currentTimeMillis();
									long fl_millis = fl_time_end - fl_time_start;
									System.out.println("Fast Login total time: " + fl_millis + "ms");
								}
							}
						}
					}
				}
				else {
					response.getOutputStream().write(("Handover Request").getBytes());
					long ho_time_end = System.currentTimeMillis();
					long ho_millis = ho_time_end - fl_time_start;
					System.out.println("Fast Login to Handover react time: " + ho_millis);
				}
			}
			else if(parts[0].equals("Mutual Authentication")) {//parameters:mUid, r_a
				System.out.println("Mutual Authentication start.");
				long ma_time_start = System.currentTimeMillis();
				response.getOutputStream().write(mutual_authentication(parts[1], parts[2]).getBytes());
				long ma_time_end = System.currentTimeMillis();
				long ma_millis = ma_time_end - ma_time_start;
				System.out.println("Mutual Authentication total time (with transmission delay): " + ma_millis);
				System.out.println("Mutual Authentication succeed.");
			}
			else if(parts[0].equals("Handover")) {
				//  改成傳IP
				//	parameters : sig-cs(P-PK)(1), P-PK(2), User Profile{name(3), email(4), mUid(5)}, Autho. Level(6), ip_sas(7),
				//	〖𝑆𝑖𝑔〗_(𝑃−𝑆𝐾)(P-PK || User Profile || Autho. Set || TTL || r_b)(8), TTL(9), UAM = 〖𝑆𝑖𝑔〗_(〖𝑠𝑘〗_𝑆𝐴𝑆 ){P-PK || User Profile || Autho. Set || TTL}(10),
				//	Sig-psk(UAM, r_b)(11)

				//1. Verifies 〖𝑆𝑖𝑔〗_𝐶𝑆(P-PK) and P-PK to make sure UE’s identity using 〖𝑝𝑘〗_𝐶𝑆 to make sure P-PK is assigned by cloud server
				//2. Verifies 〖𝑆𝑖𝑔〗_(𝑃−𝑆𝐾)(P-PK || User Profile || Autho. Set || TTL || r_b) and {P-PK || User Profile || Autho. Set || TTL || r_b} using P-PK to make sure user data is given by P-PK with freshness
				//3. Verifies UAM and 〖𝑆𝑖𝑔〗_(𝑃−𝑆𝐾)( UAM , 𝑏)  using P-PK to make sure UAM is signed from UE(P-PK)
				//4. Compares UAM and {P-PK || User Profile || Autho. Set || TTL} using 〖𝑝𝑘〗_𝑆𝐴𝑆 to make sure user data is signed by Source App Server
				//5. Handover success response and update user data to sql database
				System.out.println("Handover start.");
				long ho_time_start = System.currentTimeMillis();
				if(signature_verify(cloud_server_pk, parts[2], Hex.decode(parts[1]))) {
					byte[] user_publicKey = Base64.decodeBase64(parts[2]);
					X509EncodedKeySpec user_pk_spec= new X509EncodedKeySpec(user_publicKey);
					PublicKey user_pk = keyFactory.generatePublic(user_pk_spec);
					String compare_data = parts[2] + "," + parts[3] + "," + parts[4] + "," + parts[5] + "," + parts[6] + "," + 
											parts[9] + "," + user_value.get(parts[2]);//ppk||user_profile||autho_level||TTL||r_b
					if(signature_verify(user_pk, compare_data, Hex.decode(parts[8]))) {
						if(signature_verify(user_pk, parts[10] + "," + user_value.get(parts[2]), Hex.decode(parts[11]))) {
							//byte[] sas_publicKey = Base64.decodeBase64(parts[7]);
							//X509EncodedKeySpec sas_pk_spec= new X509EncodedKeySpec(sas_publicKey);
							//PublicKey sas_pk = keyFactory.generatePublic(sas_pk_spec);
							
							byte[] sas_publicKey = Files.readAllBytes(Paths.get(keystorePath + parts[7] + ".pubkey.der"));
							X509EncodedKeySpec publicKeySpec= new X509EncodedKeySpec(sas_publicKey);					
							PublicKey sas_pk = keyFactory.generatePublic(publicKeySpec);
							
							if(signature_verify(sas_pk, parts[2] + "," + parts[3] + "," + parts[4] + "," + parts[5] + "," 
							+ parts[6] + "," + parts[9], Hex.decode(parts[10]))) 
							{	
								//hand-over success response and update SQL database
								Connection conn = SQL_connection();
								//mUid, ppk, username, email, autho_level
								Post(conn, parts[2], parts[3], parts[4], parts[5], parts[6]);
								System.out.println("Handover succeed.");
								response.getOutputStream().write(("Handover succeed.").getBytes());
								long ho_time_end = System.currentTimeMillis();
								long ho_millis = ho_time_end - ho_time_start;
								System.out.println("Handover total time: " + ho_millis + "ms");
							}
						}
					}
				}
			}
			else if(parts[0].equals("Data Request")) {
				// parameters : ID(1), ppk(2), sig-psk(datanumber, r_b)(3)
				System.out.println("Data Request start.");
				try {
					long dr_time_start = System.currentTimeMillis();
					byte[] user_publicKey = Base64.decodeBase64(parts[2]);
					X509EncodedKeySpec user_pk_spec= new X509EncodedKeySpec(user_publicKey);
					PublicKey user_pk = keyFactory.generatePublic(user_pk_spec);
					String compare_data = parts[1] + "," + user_value.get(parts[2]);//datanumber + r_b
					if(signature_verify(user_pk, compare_data, Hex.decode(parts[3]))) {
						//find data authority level = user authority level with datatype equals user request datatype.(optional)
						Connection conn = SQL_connection();
						String Query = "SELECT autho_level FROM app_server_userdata.app_userdata WHERE ppk=\"" + parts[2] + "\"";
						Statement stmt = conn.createStatement();
						ResultSet rs = stmt.executeQuery(Query);
						if(rs.next()) {//whether user's authority level exists
							String autho_level = rs.getString("autho_level");
							String response_message = "Data Response";
							Query = "SELECT datamodel FROM model_data.models WHERE autho_level='" + autho_level + "'AND ID='" + parts[1] + "'" ;
							ResultSet rs1 = stmt.executeQuery(Query);
							if(rs1.next()) {//whether data exists and authority level matches
								response_message = response_message + "," + rs1.getString("datamodel");//原本應該要附上簽章, 但懶得寫
								System.out.println("Data Request succeed.");
								response.getOutputStream().write((response_message).getBytes());
								long dr_time_end = System.currentTimeMillis();
								long dr_millis = dr_time_end - dr_time_start;
								System.out.println("Data Request total time: " + dr_millis);
							}
							else {
								System.out.println("Data Request Failed.");
								response_message = "Data Request Failed." + "," + "NULL";
								response.getOutputStream().write((response_message).getBytes());
							}
						}
						else{
							String response_message = "HandOver" + "," + "NULL";
							response.getOutputStream().write((response_message).getBytes());
						}
					}
					else {
						System.out.println("line 230 failed.");
						String response_message = "Data Request Failed." + "," + "NULL";
						response.getOutputStream().write((response_message).getBytes());
					}
				}
				catch(Exception e) {
					e.printStackTrace();
				}
			}
			/*暫時沒有這功能
			else if(parts[0].equals("Data Upload")) {
				//ppk(1), datatype(2), autho_level(3), datamodel(4), sig-psk(datatype, autho_level, data)(5)
				try {
					Connection conn = SQL_connection();
					String Query = "SELECT autho_level FROM app_server_userdata.app_userdata WHERE ppk=\"" + parts[2] + "\"";
					Statement stmt = conn.createStatement();
					ResultSet rs = stmt.executeQuery(Query);
					if(rs.next()) {
						if(Integer.parseInt(rs.getString("autho_level")) >= Integer.parseInt(parts[3])) {
							byte[] user_publicKey = Base64.decodeBase64(parts[1]);
							X509EncodedKeySpec user_pk_spec= new X509EncodedKeySpec(user_publicKey);
							PublicKey user_pk = keyFactory.generatePublic(user_pk_spec);
							if(signature_verify(user_pk, parts[2] + "," + parts[3] + "," + parts[4], Hex.decode(parts[5]))) {
								Query = "INSERT INTO model_data.models (datatype, autho_level, datamodel)VALUES" + "('" + parts[2] + "','" + parts[3] + "','" + parts[4] + "');";
								PreparedStatement preparedPosted = conn.prepareStatement(Query);
								preparedPosted.execute();
								SimpleDateFormat dfDate  = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
								Date currentTime = new Date(System.currentTimeMillis());
								System.out.println("User Data updated successfully at time: " + dfDate.format(currentTime));
								response.getOutputStream().write(("Data uploaded successfully at : " + dfDate.format(currentTime)).getBytes());
							}
						}
					}
					else {
						response.getOutputStream().write(("Data Upload Failed.").getBytes());
					}
				}
				catch(Exception e) {
					e.printStackTrace();
				}
			}
			else if(parts[0].equals("Revoke List Update")) {
				//parameters: ppk, sig-cs(ppk)
				Connection conn = SQL_connection();
			}*/
		}
		catch(Exception e) {
			e.printStackTrace();
			System.out.println("Data process failed.");
		}
	}
	
	public static String userdata_Query(Connection conn, String ppk) throws Exception {//get user data (user_profile, autho_level) by ppk
		try {
			String QUERY = "SELECT ppk, username, email, mUid, autho_level FROM app_server_userdata.app_userdata WHERE ppk =\""+ppk+"\"";
			Statement stmt = conn.createStatement();
			ResultSet rs = stmt.executeQuery(QUERY);
			if(rs.next()) {// if success
				String p_pk = rs.getString("ppk");
				String username = rs.getString("username");
				String email = rs.getString("email");
				String mUid = rs.getString("mUid");
				String autho_level = rs.getString("autho_level");
				System.out.println("Query Finished.");
				return p_pk + "," + username + "," + email + "," + mUid + "," + autho_level;
			}
			else { return "Query Failed."; }
		}
		catch(Exception e) {
			e.printStackTrace();
			return "Query Failed.";
		}
	}
	
	public static void Post(Connection conn, String ppk, String username, String email, String mUid, String autho_level) throws Exception {
		//stores user data(mid, p-pk, user profile, autho. set) everytime when gets data from user or cloud server with TTL
		try {
			SimpleDateFormat dfDate  = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date currentTime = new Date(System.currentTimeMillis());
			PreparedStatement check_data_exists = conn.prepareStatement("SELECT ppk from app_server_userdata.app_userdata WHERE ppk=\""+ppk+"\"");
			ResultSet rs = check_data_exists.executeQuery();
			if(!rs.next()) {//No data found
				PreparedStatement preparedPosted = conn.prepareStatement("INSERT INTO app_server_userdata.app_userdata (ppk, username, email, mUid, autho_level,  data_stored_time) VALUES" + 
														" ('"+ppk+"','"+username+"','"+email+"','"+mUid+"','"+autho_level+"','"+dfDate.format(currentTime)+"');");
				preparedPosted.execute();
				System.out.println("User Data posted at time: " + dfDate.format(currentTime));
			}
			else {//Data already exists - Update(Option)
				//String Query = "UPDATE app_server_userdata.app_userdata SET ppk = \"" + ppk + "\" username = \"" + username + "\" email = \"" + email + "\" mUid = \"" + mUid + "\" autho_level = \"" + autho_level + "\" data_stored time = \"" + currentTime + "\"";
				//PreparedStatement preparedUpdated = conn.prepareStatement(Query);
				//preparedUpdated.execute();
				String Query = "UPDATE app_server_userdata.app_userdata SET data_stored time = \""+dfDate.format(currentTime)+"\" WHERE ppk = \""+ppk+"\"";
				PreparedStatement preparedUpdated = conn.prepareStatement(Query);
				preparedUpdated.execute();
				System.out.println("User Data updated at time: " + dfDate.format(currentTime));
			}
		}catch(Exception e) {System.out.println(e);}
	}
	
	public static Connection SQL_connection() throws Exception {//basic connects to MySQL database
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
	
	public static byte[] signature_gen(String data) {
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
	
	public static boolean signature_verify(PublicKey pk, String data, byte[] signature) {
		try {
			long verStartTime = System.currentTimeMillis();
			Signature sign = Signature.getInstance("SHA256withRSA");
			byte[] bytes = data.getBytes();
			sign.initVerify(pk);
			sign.update(bytes);
			long verStopTime = System.currentTimeMillis();
			System.out.println("Signature Verify Time: " + Long.toString(verStopTime - verStartTime) + "ms");
			return sign.verify(signature);
		}
		catch (Exception e) {e.printStackTrace();}
		return false;
	}
	
	private static final long serialVersionUID = 1L;
       
    /**
     * @throws Exception 
     * @see HttpServlet#HttpServlet()
     */
    public App_Server() throws Exception {
        super();
        // TODO Auto-generated constructor stub
        keyFactory = KeyFactory.getInstance("RSA");
        KeyPair kp = getKeyPair(keyFactory);
        publicKey = kp.getPublic();
        privateKey = kp.getPrivate();
        byte[] publicKeyData = Files.readAllBytes(Paths.get(keystorePath + "cs_pubkey.der"));
        X509EncodedKeySpec publicKeySpec= new X509EncodedKeySpec(publicKeyData);
        cloud_server_pk = keyFactory.generatePublic(publicKeySpec);
        System.out.println("Initilization Finished.");
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
		if (request.getParameter("toAppServer")!= null) {
			String Data = request.getParameter("toAppServer");//all received data
			if(Data.split(",")[0].equals("Registration")) {
				//request.getRequestDispatcher("https://140.117.172.202:8443/ServletTest").forward(request, response);
				System.out.println("Registration.");
			}
			else {
				//System.out.println("processdata.");
				processdata(Data, response);
			}
		}
	}
}
