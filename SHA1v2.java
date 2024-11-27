import java.util.Scanner;
import java.security.MessageDigest;

class SHA1v2 {
	public static void main(String[] args) throws Exception {
		Scanner sc = new Scanner(System.in);
		System.out.println("Enter the message : ");
		String message = sc.next();
        sc.close();
		System.out.println("Message Digest is = " + sha1(message));
	}
	public static String sha1(String input) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA1");
		byte[] result = md.digest(input.getBytes());
		StringBuffer sb = new StringBuffer();
		for(byte byteuh: result) {
			sb.append(Integer.toString((byteuh & 0xff) + 0x100, 16).substring(1));
		}
		return sb.toString();
	}
}