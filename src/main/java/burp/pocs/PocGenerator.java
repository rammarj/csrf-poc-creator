
package burp.pocs;

import burp.IHttpRequestResponse;
import burp.util.Request;

/**
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public interface PocGenerator {

    /**
     * Returns the PoC code.
     * @param r {@link IHttpRequestResponse} object to use.
     * @return the PoC code.
     * @throws java.lang.Exception
     */
    public byte[] generate(final Request request);
    
}
