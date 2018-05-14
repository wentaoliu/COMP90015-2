package activitystreamer.server;

import java.io.IOException;
import java.net.Socket;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import activitystreamer.util.Settings;

public class Control extends Thread {

	// Represents servers in the same network,
	// directly or indirectly connected to this server.
	// Those data are obtained by receiving announcements from other servers.
	private class ServerInfo implements Comparable {

		private String id;
		private String hostname;
		private int port;
		private int load;
		private int level;
		private LocalDateTime timestamp;

		public ServerInfo(String id, String hostname, int port, int load, int level) {
			this.id = id;
			this.hostname = hostname;
			this.port = port;
			this.load = load;
			this.level = level;
			this.timestamp = LocalDateTime.now();
		}

		// Server id is used to identify each server.
		// It is immutable.
		public String getServerId() {
			return id;
		}

		public String getHostname() {
			return hostname;
		}

		public void setHostname(String hostname) {
			this.hostname = hostname;
		}

		public int getPort() {
			return port;
		}

		public void setPort(int port) {
			this.port = port;
		}

		public int getLoad() {
			return load;
		}

		public void setLoad(int load) {
			this.load = load;
		}

		public int getLevel() {
			return level;
		}

		public void setLevel(int level) {
			this.level = level;
		}

		public LocalDateTime getTimestamp() {
			return timestamp;
		}

		public void setTimestamp() {
			this.timestamp = LocalDateTime.now();
		}

		@Override
		public int compareTo(Object o) {
			ServerInfo s = (ServerInfo) o;
			int level = s.getLevel();
			String id = s.getServerId();

			if(this.level != level) {
				return level - this.level;
			} else {
				return this.id.compareTo(id);
			}
		}
	}

	// Represents users registered in this network.
	// Not necessarily registers through this server.
	// May obtained by receiving lock requests from other servers
	private class UserInfo {
		private String username;
		private String secret;

		public UserInfo(String username, String secret) {
			this.username = username;
			this.secret = secret;
		}

		public String getUsername() {
			return username;
		}

		public String getSecret() {
			return secret;
		}
	}

	// Represents a message to be sent
	// used by messages buffer
	private class Message {
		private String msg;
		private Connection con;

		public Message(String msg, Connection con) {
			this.msg = msg;
			this.con = con;
		}

		public String getMsg() {
			return msg;
		}

		public Connection getCon() {
			return con;
		}
	}

	// logger
	private static final Logger log = LogManager.getLogger();

	// server id
	private static String serverId = Settings.nextSecret();

	// List of all connections
	private static ArrayList<Connection> connections = new ArrayList<>();
	// There are only one outgoing connection of each server
	private static Connection outgoingConnection;
	private static String outgoingConnectionId;

	// List of validated server connections
	private static ArrayList<Connection> validatedServerConnections = new ArrayList<>();
	// List of validated client connections
	private static ArrayList<Connection> validatedClientConnections = new ArrayList<>();

	// List of all server info in this network (obtained from SERVER_ANNOUNCE)
	private static ArrayList<ServerInfo> allKnownServers = new ArrayList<>();

	private static boolean term=false;
	private static Listener listener;

	// List of all users registered on this server (online or offline)
	private static ArrayList<UserInfo> registeredUsers = new ArrayList<>();

	// For register workflow:
	// username & source client connection
	private static Map<String, Connection> registerRequestSources =  new HashMap<>();
	// username & number of servers waiting for response
	private static Map<String, ArrayList<Connection>> pendingRegisterRequests  = new HashMap<>();
	// username & source server connection
	private static Map<String, Connection> lockRequestSources = new HashMap<>();
	// username & number of servers waiting for response
	private static Map<String, ArrayList<Connection>> pendingLockRequests  = new HashMap<>();

	// Messages buffer
	private static Queue<Message> messageQueue = new LinkedList<>();
	// Is this server trying to reconnect to another server?
	private static Boolean reconnecting = false;

	
	protected static Control control = null;
	
	public static Control getInstance() {
		if(control==null){
			control=new Control();
		} 
		return control;
	}

	// Constructor
	private Control() {
		// start a listener
		try {
			listener = new Listener();
		} catch (IOException e1) {
			log.fatal("failed to startup a listening thread: "+e1);
			System.exit(-1);
		}

		// If the secret hasn't been assigned
		if (Settings.getSecret() == null) {
			Settings.setSecret(Settings.nextSecret());
		}
		log.info("The secret is : " + Settings.getSecret());

		initiateConnection();
		start();
	}


	// If a remote server is specified,
	// try to make a new connection to it and require authentication.
	public void initiateConnection(){
		// make a connection to another server if remote hostname is supplied
		if(Settings.getRemoteHostname()!=null){
			try {
				Connection c = outgoingConnection(
						new Socket(Settings.getRemoteHostname(),
								Settings.getRemotePort()));

				// Send an authentication message
				JSONObject obj = new JSONObject();
				obj.put("command", "AUTHENTICATE");
				obj.put("secret", Settings.getSecret());
				c.writeMsg(obj.toJSONString());
				// The parent server certainly is a valid server.
				validatedServerConnections.add(c);

				log.info("Sending authentication request");
			} catch (IOException e) {
				log.error("failed to make connection to "
						+ Settings.getRemoteHostname() + ":"
						+ Settings.getRemotePort());
				// If the initial connection couldn't be established,
				// just quit the program.
				System.exit(-1);
			}
		}
	}

	/*
	 * Processing incoming messages from the connection.
	 * Return true if the connection should close.
	 */
	public synchronized boolean process(Connection con,String msg) {
		JSONParser parser = new JSONParser();
		// The request JSON Object and response JSON Object
		JSONObject reqObj;
		JSONObject resObj = new JSONObject();

		try {
			// try to un-marshal the json message
			reqObj = (JSONObject) parser.parse(msg);
		} catch (ParseException e1) {
			responseToInvalidMessage(con, "JSON parse error while parsing message");

			log.error("Invalid JSON object");
			return true;
		}

		if (!reqObj.containsKey("command")) {
			responseToInvalidMessage(con, "The received message did not contain a command");

			log.error("The received message did not contain a command");
			return true;
		}

		String command = (String) reqObj.get("command");
		String username, secret;


		// Make responses according to the command type.
		switch (command) {

			// For validated server connections,
			// following (6) commands are acceptable:
			//
			// AUTHENTICATION_FAIL, SERVER_ANNOUNCE, ACTIVITY_BROADCAST,
			// LOCK_REQUEST, LOCK_ALLOW, LOCK_DENY, SERVER_INFO


			case "SERVER_INFO":
				if (!validateServerConnection(con)) return true;
				// Get and set the level of this server.
				int level = ((Number) reqObj.get("level")).intValue();
				Settings.setLevel(level);
				outgoingConnectionId = (String) reqObj.get("serverId");

				// Get and save the registered users.
				JSONArray usersJsonArray = (JSONArray) reqObj.get("users");

				for(Object s: usersJsonArray) {
					String[] user = ((String) s).split(":");
					registeredUsers.add(new UserInfo(user[0], user[1]));
				}


				log.info("server info: " + reqObj);
				return false;

			case "AUTHENTICATION_FAIL":
				if (!validateServerConnection(con)) return true;

				log.error("authentication failed: " + reqObj.get("info"));
				return true;

			case "SERVER_ANNOUNCE":
				if (!validateServerConnection(con)) return true;

				String rServerId = (String) reqObj.get("id");
				int rServerLoad = ((Number) reqObj.get("load")).intValue();
				String rServerHostname = (String) reqObj.get("hostname");
				int rServerPort = ((Number) reqObj.get("port")).intValue();
				int rServerLevel = ((Number) reqObj.get("level")).intValue();

				boolean existed = false;
				// traverse all the known servers
				// to see if we have already known this server
				for (ServerInfo s : allKnownServers) {
					if (s.getServerId().equals(rServerId)) {
						existed = true;
						s.setPort(rServerPort);
						s.setHostname(rServerHostname);
						s.setLoad(rServerLoad);
						s.setLevel(rServerLevel);
						s.setTimestamp();
					}
				}
				// if not, create a new entry to store the info
				if (!existed) {
					allKnownServers.add(new ServerInfo(rServerId, rServerHostname,
							rServerPort, rServerLoad, rServerLevel));
				}

				log.info("Server announcement from " + rServerId + "(" + rServerHostname + ":"
						+ rServerPort + "), " + rServerLoad + " connected client(s), level "
						+ rServerLevel);

				// broadcast to all other servers
				broadcastMessage(validatedServerConnections, con, reqObj);
				return false;

			case "ACTIVITY_BROADCAST":
				if (!validateServerConnection(con)) return true;

				// Broadcast to both the servers and the clients
				broadcastMessage(validatedServerConnections, con, reqObj);
				broadcastMessage(validatedClientConnections, con, reqObj);
				return false;

			case "LOCK_REQUEST":
				if (!validateServerConnection(con)) return true;

				username = (String) reqObj.get("username");
				secret = (String) reqObj.get("secret");

				// If the username is already known to this server,
				// send back lock_denied to the server requesting this name.
				if (!checkUsernameAvailability(username)) {
					resObj.put("command", "LOCK_DENIED");
					resObj.put("username", username);
					resObj.put("secret", secret);

					sendMessage(con, resObj.toJSONString());

					log.error("this username is registered in this server");
				} else {
					// If the username is not already known to this server,
					// record this username and password,
					// then broadcast lock_request to all other servers.

					resObj.put("command", "LOCK_REQUEST");
					resObj.put("username", username);
					resObj.put("secret", secret);
					// pass the original lock_request to other servers
					broadcastMessage(validatedServerConnections, con, reqObj);
					// Save this username and secret to local storage.
					registeredUsers.add(new UserInfo(username, secret));

					// Save the source connection
					lockRequestSources.put(username, con);
					// Save the servers that we sent lock_requests to.
					pendingLockRequests.put(username, new ArrayList<>(validatedServerConnections));

					log.info("lock allowed");
				}
				return false;

			case "LOCK_DENIED":
				if (!validateServerConnection(con)) return true;

				username = (String) reqObj.get("username");
				secret = (String) reqObj.get("secret");

				// If the username has been registered on this server,
				// then remove local username and secret
				registeredUsers.removeIf(user -> user.getUsername().equals(username));

				// If the username is registered by a client of this server,
				// and now we need to refuse its register request
				if (registerRequestSources.containsKey(username)) {
					resObj.put("command", "REGISTER_FAILED");
					resObj.put("info", username + " is already registered with the system");

					sendMessage(registerRequestSources.get(username), resObj.toJSONString());
					log.error("this username is registered in this server");

					// Remove it from pending register request list.
					registerRequestSources.remove(username);
					pendingRegisterRequests.remove(username);


					// broadcast LOCK_CANCEL to all servers
					JSONObject resObj1 = new JSONObject();
					resObj1.put("command", "LOCK_CANCEL");
					resObj1.put("username", username);
					resObj1.put("secret", secret);

					broadcastMessage(validatedServerConnections, null, resObj1);

					return true;
				}

				// If it is not registered by a client of this server,
				// send back to the server requesting this name.
				if (lockRequestSources.containsKey(username)) {
					sendMessage(lockRequestSources.get(username), reqObj.toJSONString());

					// Remove it from pending lock request list.
					lockRequestSources.remove(username);
					pendingLockRequests.remove(username);
				}

				return false;

			case "LOCK_ALLOWED":
				if (!validateServerConnection(con)) return true;

				username = (String) reqObj.get("username");

				// If the username is registered by a client of this server
				if (pendingRegisterRequests.containsKey(username)) {

					// connections
					ArrayList<Connection> remainingConnections =
							new ArrayList<>(pendingRegisterRequests.get(username));

					// find the common connection(s) in the current connections
					// and connections when the original request was sent.
					// (Because we may sent lock requests to some servers,
					// but they quited before sending a feedback).
					remainingConnections.retainAll(validatedServerConnections);
					// If there is no connection in common,
					// the registration is successful.
					if(remainingConnections.isEmpty()) {

						resObj.put("command", "REGISTER_SUCCESS");
						resObj.put("info", "register success for " + username);

						// Save as a valid client connection.
						validatedClientConnections.add(registerRequestSources.get(username));

						sendMessage(registerRequestSources.get(username), resObj.toJSONString());

						// Remove from pending list
						pendingRegisterRequests.remove(username);
						registerRequestSources.remove(username);

						log.info(username + " registered successfully");
					}
					// Otherwise we have to wait for more responses.
					return false;
				}

				// If this username is requested by a server,
				// the process is similar.
				if (pendingLockRequests.containsKey(username)) {

					ArrayList<Connection> remainingConnections =
							new ArrayList<>(pendingLockRequests.get(username));

					remainingConnections.retainAll(validatedServerConnections);
					// If there is no connection in common,
					// we should send lock_allow to the original server.
					if(remainingConnections.isEmpty()) {
						sendMessage(lockRequestSources.get(username), reqObj.toJSONString());

						// Remove from pending list
						pendingLockRequests.remove(username);
						lockRequestSources.remove(username);

						log.info(username + " lock allowed");
					}
					// Otherwise we have to wait for more responses.
					return false;
				}

				return false;

			case "LOCK_CANCEL":
				if (!validateServerConnection(con)) return true;

				username = (String) reqObj.get("username");

				// remove the username and password from local storage
				registeredUsers.removeIf(user -> user.getUsername().equals(username));

				// Then pass the message on
				broadcastMessage(validatedServerConnections, con, reqObj);

				return false;



			// For validated client connections, following commands are acceptable:
			// ACTIVITY_MESSAGE, LOGOUT

			case "ACTIVITY_MESSAGE":
				if (!validateClientConnection(con)) return true;

				// validate the provided credential
				if (!validateUser(reqObj)) {
					resObj.put("command", "AUTHENTICATION_FAIL");
					resObj.put("info", "the supplied secret is incorrect");
					sendMessage(con, resObj.toJSONString());

					log.error("activity message authentication failed");
					return true;
				}

				// Extract the activity object from the original message.
				JSONObject activity = (JSONObject) reqObj.get("activity");
				resObj.put("command", "ACTIVITY_BROADCAST");
				resObj.put("activity", activity);
				// Send to the other clients and servers
				broadcastMessage(validatedServerConnections, con, resObj);
				broadcastMessage(validatedClientConnections, null, resObj);

				log.info("broadcast message: " + resObj.toJSONString());
				return false;

			case "LOGOUT":
				if(!validateClientConnection(con)) return true;
				// just close the connection
				return true;


			// For any connection, following commands are acceptable:
			// AUTHENTICATE, LOGIN, REGISTER

			case "AUTHENTICATE":
				if (validatedServerConnections.contains(con)) {
					responseToInvalidMessage(con, "the server had already authenticated");

					log.error("the server had already authenticated");
					return true;
				}

				secret = (String) reqObj.get("secret");
				// if and only if the secrets match, authenticate success
				if (secret.equals(Settings.getSecret())) {
					// If authentication success,
					// Send some information to the new server:
					// the level of the new server, and
					// a list of registered user info.
					resObj.put("command", "SERVER_INFO");
					resObj.put("level", Settings.getLevel() + 1);
					resObj.put("serverId", serverId);

					// Build a json array containing all registered user info.
					JSONArray usersArray = new JSONArray();
					for(UserInfo u : registeredUsers) {
						usersArray.add(u.getUsername() + ":" + u.getSecret());
					}

					resObj.put("users", usersArray);

					sendMessage(con, resObj.toJSONString());

					log.info("authentication success");
					validatedServerConnections.add(con);
					return false;
				} else {
					resObj.put("command", "AUTHENTICATION_FAIL");
					resObj.put("info", "the supplied secret is incorrect: " + secret);
					sendMessage(con, resObj.toJSONString());
					log.error("authentication failed");
					return true;
				}

			case "LOGIN":
				username = (String) reqObj.get("username");
				if (validateUser(reqObj)) {
					// for a success login attempt
					resObj.put("command", "LOGIN_SUCCESS");
					resObj.put("info", "logged in as " + username);
					sendMessage(con, resObj.toJSONString());

					validatedClientConnections.add(con);
					log.info("logged in as " + username);
				} else {
					// for a failed login attempt
					resObj.put("command", "LOGIN_FAILED");
					resObj.put("info", "attempt to login with wrong secret");
					sendMessage(con, resObj.toJSONString());
					log.error("login failed");
					return true;
				}

				// if the client logged in successfully,
				// we will check whether it needs to be redirected to another server.
				for (ServerInfo s : allKnownServers) {
					if (s.getLoad() < (validatedClientConnections.size() - 2)) {
						// there is a server with a load at least 2 clients less
						resObj.put("command", "REDIRECT");
						resObj.put("hostname", s.getHostname());
						resObj.put("port", s.getPort());
						sendMessage(con, resObj.toJSONString());
						log.info("redirect to another server");
						return true;
					}
				}
				// only if the client is authenticated and won't be redirected,
				// this connection shouldn't be closed.
				return false;


			case "REGISTER":
				if (validatedClientConnections.contains(con)) {
					responseToInvalidMessage(con, "the client has logged in");
					return true;
				}

				username = (String) reqObj.get("username");
				secret = (String) reqObj.get("secret");

				// if the username is available on this server
				if (checkUsernameAvailability(username)) {
					// Temporarily store this username and secret to local storage
					registeredUsers.add(new UserInfo(username, secret));

					if(allKnownServers.size() > 0) {
						// if there are other servers in this network,
						// we have to check other servers for this username
						resObj.put("command", "LOCK_REQUEST");
						resObj.put("username", username);
						resObj.put("secret", secret);

						// broadcast lock_request to all other servers
						broadcastMessage(validatedServerConnections, con, resObj);
						// store the connected server
						pendingRegisterRequests.put(username, new ArrayList<>(validatedServerConnections));
						// store which client registers this username
						registerRequestSources.put(username, con);

						log.info("sending out lock requests");
						return false;
					} else {
						resObj.put("command", "REGISTER_SUCCESS");
						resObj.put("info", "register success for " + username);

						validatedClientConnections.add(con);

						log.info(username + " registered successfully");
						return false;
					}
				} else { // if the username is taken
					resObj.put("command", "REGISTER_FAILED");
					resObj.put("info", username + " is already registered with the system");
					sendMessage(con, resObj.toJSONString());
					log.error("this username is registered in this server");
					return true;
				}

			default:
				break;
		}

		return true;
	}
	
	/*
	 * The connection has been closed by the other party.
	 */
	public synchronized void connectionClosed(Connection con){
		if(!term) {

			connections.remove(con);
			validatedClientConnections.remove(con);
			validatedServerConnections.remove(con);
			con.closeCon();

			// If the closed connection is our outgoing connection,
			// We have to try to reconnect to another server.
			if(outgoingConnection == con) {

				outgoingConnection = null;

				allKnownServers.removeIf(server -> server.getServerId().equals(outgoingConnectionId));
				// sort all known servers by level and id
				Collections.sort(allKnownServers);

				// Firstly, try to find a server with higher level,
				// from (current level + 1) to 0
				for(ServerInfo s : allKnownServers) {
					// Find the first server has a higher level
					if(s.getLevel() < Settings.getLevel()) {
						reconnect(s.getHostname(), s.getPort());
						return;
					}
				}

				// If no one was found,
				// then try to find a server in the same level,
				// but with a greater id (alphabetical).
				for(ServerInfo s : allKnownServers) {
					// Find the first server has a higher level
					if(s.getLevel() == Settings.getLevel()
							&& serverId.compareTo(s.getServerId()) > 0) {
						reconnect(s.getHostname(), s.getPort());
						return;
					}
				}

				// If still no one found, this server will become the root server,
				// we won't try to reconnect to any server.

			}
		}
	}

	/*
	 * Try to reconnect to a server if the current parent server is down.
	 */
	public void reconnect(String hostname, int port) {
		try {
			reconnecting = true;
			log.info("trying to reconnect to " + hostname + ":" + port);
			Connection c = outgoingConnection(
					new Socket(hostname, port));



			// Send an authentication message
			JSONObject obj = new JSONObject();
			obj.put("command", "AUTHENTICATE");
			obj.put("secret", Settings.getSecret());
			c.writeMsg(obj.toJSONString());
			// The parent server is a valid server.
			validatedServerConnections.add(c);

			reconnecting = false;
			clearBuffer();

			log.info("Sending authentication request");
		} catch (IOException e) {
			log.error("failed to make connection to "
					+ Settings.getRemoteHostname() + ":"
					+ Settings.getRemotePort());
			// If the initial connection couldn't be established,
			// just quit the program.
			System.exit(-1);
		}
	}
	
	/*
	 * A new incoming connection has been established, and a reference is returned to it
	 */
	public synchronized Connection incomingConnection(Socket s) throws IOException{
		log.debug("incoming connection: "+Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		return c;
	}
	
	/*
	 * A new outgoing connection has been established, and a reference is returned to it
	 */
	public synchronized Connection outgoingConnection(Socket s) throws IOException{
		log.debug("outgoing connection: "+Settings.socketAddress(s));
		Connection c = new Connection(s);
		connections.add(c);
		outgoingConnection = c;
		return c;
	}
	
	@Override
	public void run(){
		log.info("using activity interval of "+Settings.getActivityInterval()+" milliseconds");
		while(!term){
			// do something with 5 second intervals in between
			try {
				Thread.sleep(Settings.getActivityInterval());
			} catch (InterruptedException e) {
				log.info("received an interrupt, system is shutting down");
				break;
			}
			if(!term){
				log.info("Sending server announcement");
				term=doActivity();
			}
			
		}
		log.info("closing "+ connections.size()+" connections");
		// clean up
		for(Connection connection : connections){
			connection.closeCon();
		}
		listener.setTerm(true);
	}

	// send server announce
	public boolean doActivity(){
		// Broadcast server announce
		JSONObject obj = new JSONObject();
		obj.put("command", "SERVER_ANNOUNCE");
		obj.put("id", serverId);
		obj.put("load", validatedClientConnections.size());
		obj.put("hostname", Settings.getLocalHostname());
		obj.put("port", Settings.getLocalPort());
		obj.put("level", Settings.getLevel());

		broadcastMessage(validatedServerConnections, null, obj);

		// Refresh servers list
		// Remove the server information received 2x interval time ago.
		LocalDateTime time = LocalDateTime.now().minus(Settings.getActivityInterval(), ChronoUnit.MILLIS);
		allKnownServers.removeIf(server -> server.getTimestamp().isBefore(time));

		return false;
	}
	
	public final void setTerm(boolean t){
		term=t;
	}

	// check whether the provided username and secret are correct
	private boolean validateUser(JSONObject obj) {
		if(!obj.containsKey("username")) {
			return false;
		}
		String username = (String) obj.get("username");
		if(username.equals("anonymous")) {
			return true;
		} else {
			if(!obj.containsKey("secret")) {
				return false;
			}
			String secret = (String) obj.get("secret");
			for(UserInfo user: registeredUsers) {
				if(user.getUsername().equals(username)
						&& user.getSecret().equals(secret)) {
					return true;
				}
			}
		}
		return false;
	}

	// Check if the current connection is a valid client connection.
	private boolean validateClientConnection(Connection con) {
		return validatedClientConnections.contains(con);
	}

	// Check if the current connection is a valid server connection.
	private boolean validateServerConnection(Connection con) {
		if(validatedServerConnections.contains(con)) {
			return true;
		} else {
			JSONObject obj = new JSONObject();
			obj.put("command", "AUTHENTICATION_FAIL");
			obj.put("info", "the server is not authenticated");
			sendMessage(con, obj.toJSONString());
			return false;
		}
	}

	// Check if the username is already known on this server
	private boolean checkUsernameAvailability(String username) {
		for(UserInfo user : registeredUsers) {
			if(user.getUsername().equals(username)) return false;
		}
		return true;
	}

	private void sendMessage(Connection con, String msg) {
		if(reconnecting) {
			// If the server is reconnecting,
			// we should save the message in the buffer
			messageQueue.add(new Message(msg, con));
		} else {
			con.writeMsg(msg);
		}
	}

	private void clearBuffer() {
		// FIFO is guaranteed
		Message m = messageQueue.poll();
		while(m != null) {
			m.getCon().writeMsg(m.getMsg());
			m = messageQueue.poll();
		}
	}

	// Respond with a invalid_message command
	private void responseToInvalidMessage(Connection con, String msg) {
		JSONObject obj = new JSONObject();
		obj.put("command", "INVALID_MESSAGE");
		obj.put("info", msg);
		con.writeMsg(obj.toJSONString());
	}


	// Broadcast a message to all servers (except for the given connection)
	private void broadcastMessage(ArrayList<Connection> connections, Connection current, JSONObject res) {
		for(Connection con : connections) {
			if(con!=current) {
				sendMessage(con, res.toJSONString());

			}
		}
	}
}
