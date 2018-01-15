
package burp;

import java.net.URL;
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
     * Creates a {@link IHttpServiceImpl} using a {@link IRequestInfo}
     * @param info {@link IRequestInfo} to use.
     */
    public IHttpServiceImpl(IRequestInfo info) {
        this(info.getUrl());
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
