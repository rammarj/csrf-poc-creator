
package burp.burptab;

import burp.ITab;
import java.awt.Component;
/**
 *
 * @author Joaquin R. Martinez
 */
public class ITabImpl implements ITab, Cloneable{

    private final Component contentComponent;
    private final String tabString;
    
    /**
     * Creates a new ITabImpl object with the given title and component.
     * @param tabstring the title of the tab.
     * @param ui the component shown on this tab.
     */
    public ITabImpl(String tabstring, Component ui) {
        this.contentComponent = ui;
        this.tabString = tabstring;
    }

    /**
     * Creates a new ITabImpl object with empty title and NULL object as content component.
     */
    public ITabImpl() {
        this.contentComponent = null;
        this.tabString = "";
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
