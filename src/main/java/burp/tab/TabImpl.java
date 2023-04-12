
package burp.tab;

import burp.ITab;
import java.awt.Component;
/**
 *
 * @author Joaquin R. Martinez
 */
public class TabImpl implements ITab {

    private final Component contentComponent;
    private final String tabString;
    
    /**
     * Creates a new TabImpl object with the given title and component.
     * @param tabstring the title of the tab.
     * @param ui the component shown on this tab.
     */
    public TabImpl(String tabstring, Component ui) {
        this.contentComponent = ui;
        this.tabString = tabstring;
    }

    @Override
    public String getTabCaption() {
        return this.tabString;
    }

    @Override
    public Component getUiComponent() {
        return this.contentComponent;
    }    

}
