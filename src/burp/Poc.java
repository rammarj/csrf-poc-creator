
package burp;
/**
 * @author Joaquin R. Martinez
 */
public interface Poc {

    static final byte AJAX_POC = 1;
    static final byte HTML_POC = 2;
    static final byte OTHER = 3;
    
    /**
     * Returns the PoC code.
     * @return the PoC code.
     * @throws java.lang.Exception
     * @see #getType() 
     */
    public byte[] getPoc() throws Exception;
    /**
     * Returns the PoC type.
     * @return the PoC type.
     * @see #getPoc() 
     */
    public byte getType();
    
}
