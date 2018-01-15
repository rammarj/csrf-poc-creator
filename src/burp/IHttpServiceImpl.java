
package burp;

import java.net.URL;
/**
 *
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class IHttpServiceImpl implements IHttpService {

    private URL url;

    public IHttpServiceImpl(URL url) {
        this.url = url;
    }

    public IHttpServiceImpl(IRequestInfo info) {
        this(info.getUrl());
    }

    @Override
    public String getHost() {
        return this.url.getHost();
    }

    @Override
    public int getPort() {
        return this.url.getPort();
    }

    @Override
    public String getProtocol() {
        return this.url.getProtocol();
    }

}
