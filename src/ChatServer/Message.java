package ChatServer;

import java.util.Date;

public class Message {
	private String username;
	private Date timestamp;
	private String content;
	
	public Message(String username, Date timestamp, String content) {
		this.username = username;
		this.timestamp = timestamp;
		this.content = content;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public Date getTimestamp() {
		return timestamp;
	}
	public void setTimestamp(Date timestamp) {
		this.timestamp = timestamp;
	}
	public String getContent() {
		return content;
	}
	public void setContent(String content) {
		this.content = content;
	}

}
