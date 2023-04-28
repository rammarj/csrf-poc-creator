package burp.util;

import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;;

public class Request {

	private final String method;
	private final URL url;
	private final String requestBody;
	private final List<Header> headers;
	private final byte contentType;
	private final List<IParameter> parameters;

	public Request(String method, URL url, String requestBody, List<Header> headers, byte contentType,
			List<IParameter> parameters) {
		super();
		this.method = method;
		this.url = url;
		this.requestBody = requestBody;
		this.headers = headers;
		this.contentType = contentType;
		this.parameters = parameters;
	}

	public String getMethod() {
		return method;
	}

	public URL getUrl() {
		return url;
	}

	public String getRequestBody() {
		return requestBody;
	}

	public List<Header> getHeaders() {
		return headers;
	}

	public byte getContentType() {
		return contentType;
	}

	public List<IParameter> getParameters() {
		return parameters;
	}

	public static Request fromHTTPRequestResponse(IHttpRequestResponse hrr, IExtensionHelpers h) {
		IRequestInfo requestInfo = h.analyzeRequest(hrr);
		String body = h.bytesToString(hrr.getRequest()).substring(requestInfo.getBodyOffset());
		List<Header> headers = requestInfo.getHeaders().stream().map(next -> Header.parse(next)).toList();
		URL url = requestInfo.getUrl();
		List<IParameter> parameters = requestInfo.getParameters().stream().filter(e -> isValidParameter(e)).toList();
		return new Request(requestInfo.getMethod(), url, body, headers, requestInfo.getContentType(), parameters);
	}

	private static boolean isValidParameter(IParameter e) {
		return e.getType() == IParameter.PARAM_BODY || e.getType() == IParameter.PARAM_URL
				|| e.getType() == IParameter.PARAM_MULTIPART_ATTR;
	}

}
