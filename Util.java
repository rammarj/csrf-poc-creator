
package burp;

import burp.IParameter;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.SplittableRandom;
/**
 *
 * @author Joaquin R. Martinez
 */
public class Util {

    public static String escapeDoubleQuotes(String escaping) {
        return escaping.replace("\"", "\\\"");
    }

    public static String escapeSingleQuotes(String escape) {
        return escape.replace("'", "\\'");
    }
    
    public static String escapeBackSlashes(String escape){
        return escape.replace("\\", "\\\\");
    }

    public static String bytesToString(byte[] arg) {
        StringBuilder a = new StringBuilder();
        for (int i = 0; i < arg.length; i++) {
            byte b = arg[i];
            a.append((char) b);
        }
        return a.toString();
    }

    public static String generateRandomString(int lenght) {
        SplittableRandom splittableRandom = new SplittableRandom();
        StringBuffer a = new StringBuffer();
        for (int i = 0; i < lenght; i++) {
            int nextInt = splittableRandom.nextInt(0, 2);
            int ext = 'a';
            if (nextInt == 1) {
                ext = splittableRandom.nextInt('A', 'Z');
            } else {
                ext = splittableRandom.nextInt('a', 'z');
            }
            a.append((char) ext);
        }
        return a.toString();
    }

    public static List<Parameter> getParameters(String queryString) {
        LinkedList<Parameter> linkedList = new LinkedList<>();
        if (queryString != null) {
            String[] split = queryString.split("&");
            for (String split1 : split) {
                if (!"".equals(split1)) {
                    linkedList.add(Parameter.build(split1));
                }
            }
        }
        return linkedList;
    }

    public static String joinParameters(List<Parameter> p) {
        StringBuffer a = new StringBuffer();
        p.stream().forEach((Parameter next) -> {
            a.append(next.toString()).append("&");
        });
        a.deleteCharAt(a.lastIndexOf("&"));
        return a.toString();
    }
    /**
     * Retrieve the content type header or null if not in list.
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
    
    public static List<Header> parseHeaderList(List<String> headers){
        LinkedList<Header> a = new LinkedList<>();
        headers.stream().map((next) -> Header.build(next)).forEach((build) -> {
            a.add(build);
        });
        return a;
    }

    public static List<Parameter> toParameterList(List<IParameter> p){
        LinkedList<Parameter> a = new LinkedList<>();
        for (Iterator iterator = p.iterator(); iterator.hasNext();) {
            Parameter next = new Parameter(null, null, Parameter.Type.PARAM_URL);
            a.add(next);
        }
        return a;
    }
}
