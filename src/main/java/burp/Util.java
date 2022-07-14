package burp;

import java.util.LinkedList;
import java.util.List;
import java.util.SplittableRandom;
import java.util.stream.Collectors;
/**
 *
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Util {
    
    /**
     * Escapes backslashes and doublequotes
     * @param escape the string to escape
     * @return the escaped string
     */
    public static String escape(String escape){
        return escape.replace("\\", "\\\\").replace("\"", "\\\"");
    }
    /**
     * Generates a random string (for Multipart requests)
     * @param lenght the char number of the random string
     * @return the random string
     */
    public static String generateRandomString(int lenght) {
        SplittableRandom splittableRandom = new SplittableRandom();
        StringBuffer a = new StringBuffer();
        int nextInt, ext;
        for (int i = 0; i < lenght; i++) {
            nextInt = splittableRandom.nextInt(0, 2);
            ext = 'a';
            if (nextInt == 1) {
                ext = splittableRandom.nextInt('A', 'Z');
            } else {
                ext = splittableRandom.nextInt('a', 'z');
            }
            a.append((char) ext);
        }
        return a.toString();
    }

    /**
     * Join all parameters with a "&"
     * @param p the list of Parameters to join
     * @return the joined parameters as a string 
     */
    public static String joinParameters(List<Parameter> p) {
        return p.stream().map(Parameter::toString)
        		  .collect(Collectors.joining("&")); 
    }

    /**
     * Build a string to a list of Header objects
     * @param  headers the string to build
     * @return a list of Header objects
     */
    public static List<Header> parseHeaderList(List<String> headers){
        List<Header> a = new LinkedList<>();
        headers.stream().map(next -> Header.build(next)).forEach(build -> {
            a.add(build);
        });
        return a;
    }

    /**
     * Tries to encode some problematic HTML when adding to a form value or name.
     * @param encode the string to encode.
     * @return escaped problematic html chars.
     */
    public static String encodeHTML(String encode){
        return encode.replace("\"", "&quot;");
    }
}
