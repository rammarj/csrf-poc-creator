package burp;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
/**
 * CSRF POC Creator extension for Burp Suite
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class BurpExtender implements IBurpExtender, IContextMenuFactory, ActionListener {

    private IBurpExtenderCallbacks iexCallbacks;
    private IExtensionHelpers iexHelpers;
    private PocTabManager pocTabManager;
    private IContextMenuInvocation icMenuInvocation;
    private final JMenuItem sendMenuItem;
    private int tabCount;
    private LinkedList<JMenuItem> menuItems;
    /**Initialize all variables needed*/
    public BurpExtender() {
        this.menuItems = new LinkedList<>();
        this.sendMenuItem = new JMenuItem("send to CSRF PoC Creator");
        this.sendMenuItem.addActionListener(this);
        menuItems.add(this.sendMenuItem);
        this.tabCount = 1;
    }
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
        this.iexCallbacks = ibec;
        this.iexHelpers = ibec.getHelpers();
        this.pocTabManager = new PocTabManager();
        ibec.registerContextMenuFactory(this);
        ibec.setExtensionName("CSRF PoC Creator");
        this.iexCallbacks.addSuiteTab(new Tab("CSRF PoC", this.pocTabManager));
    }
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation icmi) {
        this.icMenuInvocation = icmi;
        byte invocation_context = icmi.getInvocationContext();
        if (invocation_context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                || invocation_context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY
                || invocation_context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            return menuItems;
        }
        return null;
    }
    /**This method is executed when the "send to csrf ..." was clicked*/
    @Override
    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse[] selectedMessages = this.icMenuInvocation.getSelectedMessages();
        for (IHttpRequestResponse ihrr : selectedMessages) {
            try {
                AjaxPoc PoC = new AjaxPoc(ihrr);
                this.pocTabManager.addTab(String.valueOf((this.tabCount++)), ihrr, PoC.getPoc());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this.pocTabManager, ex.getMessage());
            }
        }
    }
    /**
     * Creates the CSRF POC CREATOR tab
     */
    private class PocTabManager extends JTabbedPane {
        /**Ads pocString new tab within this tab with all requestInfo about the poc
         */
        public void addTab(String title, IHttpRequestResponse request, byte[] poc) {
            PocCreatorTab pocCreatorTab = new PocCreatorTab(request, poc);
            addTab(title, pocCreatorTab);
            int index = getTabCount() - 1;
            JPanel tabContainer = new JPanel();
            tabContainer.setOpaque(false);
            tabContainer.add(new JLabel(getTitleAt(index), getIconAt(index), JLabel.LEFT));
            CloseIcon closeIcon = new CloseIcon();
            JButton closeTabButton = new JButton(closeIcon);
            closeTabButton.setPreferredSize(new Dimension(closeIcon.getIconWidth(), closeIcon.getIconHeight()));
            closeTabButton.addActionListener((ActionEvent e) -> {
                int indexOfTab = indexOfTab(title); //tabs title does not change
                if (indexOfTab != -1) {
                    removeTabAt(indexOfTab);
                }
            });
            tabContainer.add(closeTabButton);
            setTabComponentAt(index, tabContainer);
        }
    }
    /**
     * POC Creator tab
     */
    private class PocCreatorTab extends JPanel implements ActionListener {

        private ITextEditor textEditor;
        private IMessageEditor messageEditor;
        private JButton saveButton, copyButton;//, btn_close;
        private JFileChooser saveFileDialog;

        /**
         * Creates pocString new tab for pocString poc
         *
         * @param req the request to show on the left
         * @param poc the poc code
         */
        PocCreatorTab(IHttpRequestResponse req, byte[] poc) {
            super(new BorderLayout(10, 10));
            this.saveButton = new JButton("save to file");
            this.copyButton = new JButton("copy");
            this.saveButton.setForeground(Color.blue);
            this.copyButton.addActionListener(this);
            this.saveButton.addActionListener(this);
            this.saveFileDialog = new JFileChooser();
            /*Create pocString TextEditor*/
            this.textEditor = iexCallbacks.createTextEditor();
            /*Making our message editor great with burp normal popup menu*/
            this.messageEditor = iexCallbacks.createMessageEditor(new IMessageEditorController() {
                @Override
                public IHttpService getHttpService() {
                    IRequestInfo analyzeRequest = iexHelpers.analyzeRequest(req);
                    return new IHttpServiceImpl(analyzeRequest);
                }

                @Override
                public byte[] getRequest() {
                    return messageEditor.getMessage();
                }

                @Override
                public byte[] getResponse() {
                    return req.getResponse();
                }
            }, true);
            JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            splitPane.add(this.messageEditor.getComponent());
            splitPane.add(this.textEditor.getComponent());
            add("Center", splitPane);
            //buttons panel
            JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            buttonsPanel.add(this.copyButton);
            buttonsPanel.add(this.saveButton);
            //add buttons to end
            add("South", buttonsPanel);
            this.textEditor.setText(poc);
            this.messageEditor.setMessage(req.getRequest(), true);
            iexCallbacks.customizeUiComponent(this);//burp lookandfeel
        }

        /**
         * When pocString button is clicked into this tab
         */
        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == this.copyButton) {
                copy();
            } else if (e.getSource() == this.saveButton) {
                save();
            }
        }

        /**
         * Passes the poc code to the system clipboard
         */
        private void copy() {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(iexCallbacks.getHelpers()
                    .bytesToString(this.textEditor.getText())), null);
        }

        private void save() {
            int showSaveDialog = this.saveFileDialog.showSaveDialog(this.textEditor.getComponent());
            if (showSaveDialog == JFileChooser.APPROVE_OPTION) {
                try {
                    File file = this.saveFileDialog.getSelectedFile();
                    try (FileWriter fileWriter = new FileWriter(file); 
                            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter)) {
                        bufferedWriter.write(iexCallbacks.getHelpers().bytesToString(this.textEditor.getText()));
                        bufferedWriter.flush();
                        fileWriter.flush();
                    }
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(this, ex, "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        }

    }
    /**
     * Ajax CSRF POCs
     */
    private class AjaxPoc implements Poc {

        private final IHttpRequestResponse request;

        /**
         * Creates ajax pocs
         *
         * @param r the {@link IHttpRequestResponse} to work
         */
        public AjaxPoc(IHttpRequestResponse r) {
            this.request = r;
        }

        @Override
        public byte[] getPoc() {
            String lineSeparator = System.lineSeparator();
            StringBuilder pocString = new StringBuilder();
            pocString.append("<html>").append(lineSeparator).append("  <!-- CSRF PoC - generated by Burp Suite i0 SecLab plugin -->").append(lineSeparator);
            pocString.append("<body>").append(lineSeparator).append("    <script>\n      function submitRequest()").append(lineSeparator);
            pocString.append("      {").append(lineSeparator).append("        var xhr = new XMLHttpRequest();").append(lineSeparator);
            String method;
            IRequestInfo requestInfo = iexHelpers.analyzeRequest(this.request);
            method = requestInfo.getMethod();
            pocString.append("        xhr.open(\"").append(method).append("\", \"");

            if ("GET".equals(method)) {
                pocString.append(this.request.getUrl()).append("\", true);").append(lineSeparator);
                pocString.append("        xhr.send();\n");
            } else {
                pocString.append(this.request.getUrl()).append("\", true);").append(lineSeparator);
                String body = iexHelpers.bytesToString(this.request.getRequest()).substring(requestInfo.getBodyOffset());
                body = Util.escapeBackSlashes(body);
                body = Util.escapeDoubleQuotes(body);
                String accept = "xt/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
                String content = "text/plain";
                String language = "es-ES,es;q=0.8";
                for (Parameter next : Util.parseHeaderList(requestInfo.getHeaders())) {
                    if ("Accept".equals(next.getName())) {
                        accept = next.getValue();
                    }
                    if ("Content-Type".equals(next.getName())) {
                        content = next.getValue();
                    }
                    if ("Accept-Language".equals(next.getName())) {
                        language = next.getValue();
                    }
                }
                pocString.append("        xhr.setRequestHeader(\"Accept\", \"").append(accept).append("\");").append(lineSeparator);
                pocString.append("        xhr.setRequestHeader(\"Content-Type\", \"").append(content).append("\");").append(lineSeparator);
                pocString.append("        xhr.setRequestHeader(\"Accept-Language\", \"").append(language).append("\");").append(lineSeparator);
                pocString.append("        xhr.withCredentials = true;").append(lineSeparator).append("        var body = ");

                if (requestInfo.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART) {
                    String[] lines = body.split("\r\n");
                    for (int i = 0; i < lines.length; i++) {
                        String line = lines[i];
                        if (i == lines.length - 1) {
                            pocString.append("\"").append(line).append("\\r\\n\";").append(lineSeparator);
                        } else {
                            pocString.append("\"").append(line).append("\\r\\n\" +").append(lineSeparator);
                        }
                    }
                } else {
                    pocString.append("\"").append(body).append("\";").append(lineSeparator);
                }
                pocString.append("        var aBody = new Uint8Array(body.length);").append(lineSeparator);
                pocString.append("        for (var i = 0; i < aBody.length; i++)").append(lineSeparator);
                pocString.append("          aBody[i] = body.charCodeAt(i); ").append(lineSeparator);
                pocString.append("        xhr.send(new Blob([aBody]));").append(lineSeparator);
            }
            pocString.append("      }").append(lineSeparator).append("    </script>\n    <form action=\"#\">").append(lineSeparator);
            pocString.append("      <input type=\"button\" value=\"Submit request\" onclick=\"submitRequest();\" />").append(lineSeparator);
            pocString.append("    </form>").append(lineSeparator).append("  </body>").append(lineSeparator).append("</html>");
            return pocString.toString().getBytes();
        }

        @Override
        public byte getType() {
            return this.AJAX_POC;
        }
    }
    /**
     * Other kind of POCs goes here (HTML, ... like burp pro CSRF POCs)
     */
}
