package burp.tab;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IHttpServiceImpl;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;

public class MessageEditorController implements IMessageEditorController {
	
	private IHttpRequestResponse request;
	private IMessageEditor messageEditor;

	public MessageEditorController(IHttpRequestResponse request, IMessageEditor messageEditor) {
		this.request = request;
		this.messageEditor = messageEditor;
	}
	
	@Override
    public IHttpService getHttpService() {
        IRequestInfo analyzeRequest = BurpExtender.getBurpExtenderCallbacks().getHelpers().analyzeRequest(this.request);
        return new IHttpServiceImpl(analyzeRequest);
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
