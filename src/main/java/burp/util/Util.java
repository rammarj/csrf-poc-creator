package burp.util;

import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SplittableRandom;
import java.util.random.RandomGenerator;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

/**
 *
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Util {

	/**
	 * Escapes backslashes and doublequotes
	 * 
	 * @param escape the string to escape
	 * @return the escaped string
	 */
	public static String escape(String escape) {
		return escape.replace("\\", "\\\\").replace("\"", "\\\"");
	}

	/**
	 * Generates a random string (for Multipart requests)
	 * 
	 * @param lenght the char number of the random string
	 * @return the random string
	 */
	public static String generateRandomString(int lenght) {
		RandomGenerator random = new SplittableRandom();
		StringBuffer a = new StringBuffer();
		for (int i = 0; i < lenght; i++) {
			int c = random.nextInt(0, 2) == 1 ? random.nextInt('A', 'Z') : random.nextInt('a', 'z');
			a.append((char) c);
		}
		return a.toString();
	}

	/**
	 * Tries to encode some problematic HTML when adding to a form value or name.
	 * 
	 * @param encode the string to encode.
	 * @return escaped problematic html chars.
	 */
	public static String encodeHTML(String encode) {
		return encode.replace("\"", "&quot;");
	}

}
