
package burp;

/**
 *
 * @author Joaquin R. Martinez
 */
public class Header extends Parameter{
    
    public Header(String name, String value) {
        super(name, value, Type.PARAM_HEADER);        
    }

    public Header() {
        this("", "");
    }   
    
    public static Header build(String header){
        if(header == null)
            throw new NullPointerException("header is null");
        String[] split = header.split(":");
        String name = split[0].trim(), value="";
        if (split.length>1) {
            value = split[1].trim();
        }
        return new Header(name, value);
    }
    
    
}
