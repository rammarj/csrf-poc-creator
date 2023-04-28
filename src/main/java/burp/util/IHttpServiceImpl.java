
package burp.util;

import java.net.URL;

import burp.IHttpService;
import burp.IRequestInfo;
/**
 *
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class IHttpServiceImpl implements IHttpService {

    private URL url;

    /**
     * Creates a {@link IHttpServiceImpl} using a {@link URL}.
     * @param url the url for this http service
     */
    public IHttpServiceImpl(URL url) {
        this.url = url;
    }

    /**
     * @return the host
     */
    @Override
    public String getHost() {
        return this.url.getHost();
    }

    /**
     * @return the port
     */
    @Override
    public int getPort() {
        return this.url.getPort();
    }

    /**
     * @return the protocol
     */
    @Override
    public String getProtocol() {
        return this.url.getProtocol();
    }

}
