
package burp.pocs;

import burp.util.Request;

/**
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public interface PocGenerator {

    /**
     * Returns the PoC code.
     * @param r {@link Request} object to use.
     * @return the PoC code.
     * @throws java.lang.Exception
     */
    public byte[] generate(final Request request);
    
}
