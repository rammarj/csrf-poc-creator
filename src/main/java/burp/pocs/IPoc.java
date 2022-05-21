
package burp.pocs;

import burp.IHttpRequestResponse;

/**
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public interface IPoc {

    /**
     * Returns the PoC code.
     * @param r {@link IHttpRequestResponse} object to use.
     * @return the PoC code.
     * @throws java.lang.Exception
     */
    public byte[] getPoc(final IHttpRequestResponse r) throws Exception;
    
}
