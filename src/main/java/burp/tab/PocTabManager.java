
package burp.tab;

import java.awt.Dimension;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

/**
 * Creates the CSRF POC CREATOR tab
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */

public class PocTabManager extends JTabbedPane {

	private static final long serialVersionUID = 1L;

	/**
     * Ads pocString new tab within this tab with all requestInfo about the poc
     * @param title the title of the tab
     * @param pocCreatorTab the tab 
     */
    public void addTab(final String title, final PocCreatorTab pocCreatorTab) {        
        super.addTab(title, pocCreatorTab);
        int index = getTabCount() - 1;
        JPanel tabContainer = createTabContainer(title);
        setTabComponentAt(index, tabContainer);
    }
    
    private JPanel createTabContainer(String title) {
        JPanel tabContainer = new JPanel();
        tabContainer.setOpaque(false);
        tabContainer.add(new JLabel(title));
        JButton closeTabButton = createTabButton(title);
        tabContainer.add(closeTabButton);
        return tabContainer;
    }
    
    private JButton createTabButton(String title) {
        CloseIcon closeIcon = new CloseIcon();
        JButton closeTabButton = new JButton(closeIcon);
        Dimension closeIconDimension = new Dimension(closeIcon.getIconWidth(), closeIcon.getIconHeight());
        closeTabButton.setPreferredSize(closeIconDimension);
        closeTabButton.addActionListener(e -> removeTab(title));
        return closeTabButton;
    }

	private void removeTab(String title) {
		int indexOfTab = indexOfTab(title); //tabs title does not change
        if (indexOfTab != -1) {
            removeTabAt(indexOfTab);
        }
	}
    
}
