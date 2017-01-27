
package burp;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.SplittableRandom;
/**
 *
 * @author Joaquin R. Martinez
 */
public class Util {
    /**
     * Escapes double coutes
     * @param escaping the string to escape
     * @return the escaped string
     */
    public static String escapeDoubleQuotes(String escaping) {
        return escaping.replace("\"", "\\\"");
    }
    /**
     * Escapes single quotes
     * @param escape the string to escape
     * @return the escaped string
     */
    public static String escapeSingleQuotes(String escape) {
        return escape.replace("'", "\\'");
    }
    /**
     * Escapes backslashes
     * @param escape the string to escape
     * @return the escaped string
     */
    public static String escapeBackSlashes(String escape){
        return escape.replace("\\", "\\\\");
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
     * Builds objects of Parameters passed as a string
     * @param params the string to build
     * @return a list of Parameter objects
     */
    public static List<Parameter> getParameters(String params) {
        LinkedList<Parameter> linkedList = new LinkedList<>();
        if (params != null) {
            String[] split = params.split("&");
            for (String split1 : split) {
                if (!"".equals(split1)) {
                    linkedList.add(Parameter.build(split1));
                }
            }
        }
        return linkedList;
    }
    /**
     * Join all parameters with a "&"
     * @param p the list of Parameters to join
     * @return the joined parameters as a string 
     */
    public static String joinParameters(List<Parameter> p) {
        StringBuffer a = new StringBuffer();
        p.stream().forEach((Parameter next) -> {
            a.append(next.toString()).append("&");
        });
        a.deleteCharAt(a.lastIndexOf("&"));
        return a.toString();
    }
    /**
     * Retrieve the content type header or null if not is in list.
     * @param p List in to search.
     * @return The content type or null.
     */
    public static Header getContentType(List<Header> p){
        Parameter.Type type = Parameter.Type.PARAM_UNKNOWN;
        for (Iterator<Header> iterator = p.iterator(); iterator.hasNext();) {
            Header next = iterator.next();
            String value = next.getValue();            
            if ("Content-Type".equals(next.getName())) {
                return next;
            }
        }
        return null;
    }
    /**
     * Build a string to a list of Header objects
     * @param  headers the string to build
     * @return a list of Header objects
     */
    public static List<Header> parseHeaderList(List<String> headers){
        LinkedList<Header> a = new LinkedList<>();
        headers.stream().map((next) -> Header.build(next)).forEach((build) -> {
            a.add(build);
        });
        return a;
    }
    /**
     * 
     */
    public static List<Parameter> toParameterList(List<IParameter> p){
        LinkedList<Parameter> a = new LinkedList<>();
        for (Iterator iterator = p.iterator(); iterator.hasNext();) {
            Parameter next = new Parameter(null, null, Parameter.Type.PARAM_URL);
            a.add(next);
        }
        return a;
    }
}
