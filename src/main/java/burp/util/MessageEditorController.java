package burp.util;

import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;

public class MessageEditorController implements IMessageEditorController {
	
	private IExtensionHelpers helpers;
	private IHttpRequestResponse request;
	private IMessageEditor messageEditor;

	public MessageEditorController(IExtensionHelpers helpers, IHttpRequestResponse request, IMessageEditor messageEditor) {
		this.helpers = helpers;
		this.request = request;
		this.messageEditor = messageEditor;
	}
	
	@Override
    public IHttpService getHttpService() {
        IRequestInfo analyzeRequest = this.helpers.analyzeRequest(this.request);
        return new HttpServiceImpl(analyzeRequest.getUrl());
    }

    @Override
    public byte[] getRequest() {
        return messageEditor.getMessage();
    }

    @Override
    public byte[] getResponse() {
        return this.request.getResponse();
    }
}
