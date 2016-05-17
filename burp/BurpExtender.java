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

    private IBurpExtenderCallbacks iex_callbacks;
    private IExtensionHelpers iex_helpers;
    private PocTabManager poc_tab_manager;
    private IContextMenuInvocation ic_menu_inv;
    private final JMenuItem send_menu_item;
    private int tab_count;
    private LinkedList<JMenuItem> menu_items;
    /**Initialize all variables needed*/
    public BurpExtender() {
        this.menu_items = new LinkedList<>();
        this.send_menu_item = new JMenuItem("send to CSRF PoC Creator");
        this.send_menu_item.addActionListener(this);
        menu_items.add(this.send_menu_item);
        this.tab_count = 1;
    }
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks ibec) {
        this.iex_callbacks = ibec;
        this.iex_helpers = ibec.getHelpers();
        this.poc_tab_manager = new PocTabManager();
        ibec.registerContextMenuFactory(this);
        ibec.setExtensionName("CSRF PoC Creator");
        this.iex_callbacks.addSuiteTab(new Tab("CSRF PoC", this.poc_tab_manager));
    }
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation icmi) {
        this.ic_menu_inv = icmi;
        byte invocation_context = icmi.getInvocationContext();
        if (invocation_context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST
                || invocation_context == IContextMenuInvocation.CONTEXT_PROXY_HISTORY
                || invocation_context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            return menu_items;
        }
        return null;
    }
    /**This method is executed when the "send to csrf ..." was clicked*/
    @Override
    public void actionPerformed(ActionEvent e) {
        IHttpRequestResponse[] selectedMessages = this.ic_menu_inv.getSelectedMessages();
        for (IHttpRequestResponse ihrr : selectedMessages) {
            try {
                AjaxPoc PoC = new AjaxPoc(ihrr);
                this.poc_tab_manager.addTab(String.valueOf((this.tab_count++)), ihrr, PoC.getPoc());
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this.poc_tab_manager, ex.getMessage());
            }
        }
    }
    /**
     * Creates the CSRF POC CREATOR tab
     */
    private class PocTabManager extends JTabbedPane {
        /**Ads a new tab within this tab with all info about the poc
         */
        public void addTab(String title, IHttpRequestResponse request, byte[] poc) {
            PocCreatorTab pocCreatorTab = new PocCreatorTab(request, poc);
            addTab(title, pocCreatorTab);
            int index = getTabCount() - 1;
            JPanel jPanel = new JPanel();
            jPanel.setOpaque(false);
            jPanel.add(new JLabel(getTitleAt(index), getIconAt(index), JLabel.LEFT));
            CloseIcon closeIcon = new CloseIcon();
            JButton jButton = new JButton(closeIcon);
            jButton.setPreferredSize(new Dimension(closeIcon.getIconWidth(), closeIcon.getIconHeight()));
            jButton.addActionListener((ActionEvent e) -> {
                int indexOfTab = indexOfTab(title); //tabs title does not change
                if (indexOfTab != -1) {
                    removeTabAt(indexOfTab);
                }
            });
            jPanel.add(jButton);
            setTabComponentAt(index, jPanel);
        }
    }
    /**
     * POC Creator tab
     */
    private class PocCreatorTab extends JPanel implements ActionListener {

        private ITextEditor text_editor;
        private IMessageEditor message_editor;
        private JButton btn_save, btn_copy;//, btn_close;
        private JFileChooser save_file_dialog;

        /**
         * Creates a new tab for a poc
         *
         * @param req the request to show on the left
         * @param poc the poc code
         */
        PocCreatorTab(IHttpRequestResponse req, byte[] poc) {
            super(new BorderLayout(10, 10));
            this.btn_save = new JButton("save to file");
            this.btn_copy = new JButton("copy");
            this.btn_save.setForeground(Color.blue);
            this.btn_copy.addActionListener(this);
            this.btn_save.addActionListener(this);
            this.save_file_dialog = new JFileChooser();
            /*Create a TextEditor*/
            this.text_editor = iex_callbacks.createTextEditor();
            /*Making our message editor great with burp normal popup menu*/
            this.message_editor = iex_callbacks.createMessageEditor(new IMessageEditorController() {
                @Override
                public IHttpService getHttpService() {
                    IRequestInfo analyzeRequest = iex_helpers.analyzeRequest(req);
                    return new IHttpServiceImpl(analyzeRequest);
                }

                @Override
                public byte[] getRequest() {
                    return message_editor.getMessage();
                }

                @Override
                public byte[] getResponse() {
                    return req.getResponse();
                }
            }, true);
            JSplitPane jSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            jSplitPane.add(this.message_editor.getComponent());
            jSplitPane.add(this.text_editor.getComponent());
            add("Center", jSplitPane);
            //buttons panel
            JPanel jPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
            jPanel.add(this.btn_copy);
            jPanel.add(this.btn_save);
            //add buttons to end
            add("South", jPanel);
            this.text_editor.setText(poc);
            this.message_editor.setMessage(req.getRequest(), true);
            iex_callbacks.customizeUiComponent(this);//burp lookandfeel
        }

        /**
         * When a button is clicked into this tab
         */
        @Override
        public void actionPerformed(ActionEvent e) {
            if (e.getSource() == this.btn_copy) {
                copy();
            } else if (e.getSource() == this.btn_save) {
                save();
            }
        }

        /**
         * Passes the poc code to the system clipboard
         */
        private void copy() {
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(iex_callbacks.getHelpers()
                    .bytesToString(this.text_editor.getText())), null);
        }

        private void save() {
            int showSaveDialog = this.save_file_dialog.showSaveDialog(this.text_editor.getComponent());
            if (showSaveDialog == JFileChooser.APPROVE_OPTION) {
                try {
                    File ff = this.save_file_dialog.getSelectedFile();
                    try (FileWriter osw = new FileWriter(ff); BufferedWriter bw = new BufferedWriter(osw)) {
                        bw.write(iex_callbacks.getHelpers().bytesToString(this.text_editor.getText()));
                        bw.flush();
                        osw.flush();
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
            String sep = System.lineSeparator();
            StringBuilder a = new StringBuilder();
            a.append("<html>").append(sep).append("  <!-- CSRF PoC - generated by Burp Suite i0 SecLab plugin -->").append(sep);
            a.append("<body>").append(sep).append("    <script>\n      function submitRequest()").append(sep);
            a.append("      {").append(sep).append("        var xhr = new XMLHttpRequest();").append(sep);
            String method;
            IRequestInfo info = iex_helpers.analyzeRequest(this.request);
            method = info.getMethod();
            a.append("        xhr.open(\"").append(method).append("\", \"");

            if ("GET".equals(method)) {
                a.append(this.request.getUrl()).append("\", true);").append(sep);
                a.append("        xhr.send();\n");
            } else {
                a.append(this.request.getUrl()).append("\", true);").append(sep);
                String body = iex_helpers.bytesToString(this.request.getRequest()).substring(info.getBodyOffset());
                body = Util.escapeBackSlashes(body);
                body = Util.escapeDoubleQuotes(body);
                String accept = "xt/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
                String content = "text/plain";
                String language = "es-ES,es;q=0.8";
                for (Parameter next : Util.parseHeaderList(info.getHeaders())) {
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
                a.append("        xhr.setRequestHeader(\"Accept\", \"").append(accept).append("\");").append(sep);
                a.append("        xhr.setRequestHeader(\"Content-Type\", \"").append(content).append("\");").append(sep);
                a.append("        xhr.setRequestHeader(\"Accept-Language\", \"").append(language).append("\");").append(sep);
                a.append("        xhr.withCredentials = true;").append(sep).append("        var body = ");

                if (info.getContentType() == IRequestInfo.CONTENT_TYPE_MULTIPART) {
                    String[] lines = body.split("\r\n");
                    for (int i = 0; i < lines.length; i++) {
                        String line = lines[i];
                        if (i == lines.length - 1) {
                            a.append("\"").append(line).append("\\r\\n\";").append(sep);
                        } else {
                            a.append("\"").append(line).append("\\r\\n\" +").append(sep);
                        }
                    }
                } else {
                    a.append("\"").append(body).append("\";").append(sep);
                }
                a.append("        var aBody = new Uint8Array(body.length);").append(sep);
                a.append("        for (var i = 0; i < aBody.length; i++)").append(sep);
                a.append("          aBody[i] = body.charCodeAt(i); ").append(sep);
                a.append("        xhr.send(new Blob([aBody]));").append(sep);
            }
            a.append("      }").append(sep).append("    </script>\n    <form action=\"#\">").append(sep);
            a.append("      <input type=\"button\" value=\"Submit request\" onclick=\"submitRequest();\" />").append(sep);
            a.append("    </form>").append(sep).append("  </body>").append(sep).append("</html>");
            return a.toString().getBytes();
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
