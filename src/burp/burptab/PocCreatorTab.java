
package burp.burptab;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IHttpServiceImpl;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.IRequestInfo;
import burp.ITextEditor;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSplitPane;

/**
 * POC Creator tab
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class PocCreatorTab extends JPanel implements ActionListener {

    private final ITextEditor textEditor;
    private final IMessageEditor messageEditor;
    private final JButton saveButton, copyButton;//, btn_close;
    private final JFileChooser saveFileDialog;
    private final IBurpExtenderCallbacks iexCallbacks;

    /**
     * Creates pocString new tab for pocString poc
     *
     * @param req the request to show on the left
     * @param poc the poc code
     */
    public PocCreatorTab(IBurpExtenderCallbacks iexCallbacks, IHttpRequestResponse req, byte[] poc) {
        super(new BorderLayout(10, 10));
        this.iexCallbacks = iexCallbacks;
        this.saveButton = new JButton("save to file");
        this.copyButton = new JButton("copy");
        this.saveButton.setForeground(Color.blue);
        this.copyButton.addActionListener(PocCreatorTab.this);
        this.saveButton.addActionListener(PocCreatorTab.this);
        this.saveFileDialog = new JFileChooser();
        /*Create pocString TextEditor*/
        this.textEditor = iexCallbacks.createTextEditor();
        /*Making our message editor great with burp normal popup menu*/
        this.messageEditor = iexCallbacks.createMessageEditor(new IMessageEditorController() {
            @Override
            public IHttpService getHttpService() {
                IRequestInfo analyzeRequest = iexCallbacks.getHelpers().analyzeRequest(req);
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
        PocCreatorTab.this.add("Center", splitPane);
        //buttons panel
        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        buttonsPanel.add(this.copyButton);
        buttonsPanel.add(this.saveButton);
        //add buttons to end
        PocCreatorTab.this.add("South", buttonsPanel);
        this.textEditor.setText(poc);
        this.messageEditor.setMessage(req.getRequest(), true);
        iexCallbacks.customizeUiComponent(PocCreatorTab.this);//burp lookandfeel
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
