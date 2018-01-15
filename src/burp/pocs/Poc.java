
package burp.pocs;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

/**
 * @author Joaquin R. Martinez
 */
public interface Poc {

    static final byte AJAX_POC = 1;
    static final byte HTML_POC = 2;
    static final byte OTHER = 3;
    
    /**
     * Returns the PoC code.
     * @param r {@link IHttpRequestResponse} object to use.
     * @return the PoC code.
     * @throws java.lang.Exception
     * @see #getType() 
     */
    public byte[] getPoc(final IExtensionHelpers iexHelpers, final IHttpRequestResponse r) throws Exception;
    /**
     * Returns the PoC type.
     * @return the PoC type.
     * @see #getPoc() 
     */
    public byte getType();
    
}
