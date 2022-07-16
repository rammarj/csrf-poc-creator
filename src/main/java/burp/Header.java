
package burp;

/**
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Header extends Parameter {
    
    /**
     * Creates a new header object with the specified name and value
     * @param name the header name
     * @param value the header value 
     */
    public Header(String name, String value) {
        super(name, value, Type.PARAM_HEADER);        
    }

    /**
     * Creates a new header object with the given strin
     * @param header the string to parse (name:value)
     * @return  The header object created
     */
    public static Header build(String header){
        if(header == null)
            throw new NullPointerException("header must not be null");
        String[] split = header.split(":");
        String name = split[0].trim(), value="";
        if (split.length > 1) {
            value = split[1].trim();
        }
        return new Header(name, value);
    }
    
}
