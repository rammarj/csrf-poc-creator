
package burp.pocs;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Contains all types of PoC's supported by this plugin.
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Pocs {
    
    private static final Map<String, IPoc> POCS = new HashMap<>() ;        
    private static Pocs poc = null;
    
    /**
     * Inaccesible constructor.
     */
    private Pocs() {
        Pocs.POCS.put("Ajax",new AjaxPoc()); 
        Pocs.POCS.put("HTML",new HtmlPoc());
        // Add more kind of PoC's
    }            

    /**
     * Initializes the types of pocs supported.
     */
    public static void initialize(){
        if(poc == null){
            Pocs.poc = new Pocs();
        }
    }
    
    /**
     * Get the {@link IPoc} object by its key.
     * @param key the key of the {@link IPoc}.
     * @return the {@link IPoc} object.
     */
    public static IPoc getPoc(String key) {
        return Pocs.POCS.get(key);
    }        
    
    /**
     * Get the {@link IPoc} as a {@link Enumeration}.
     * @return an {@link Iterator} with the keys of all {@link IPoc} objects.
     */
    public static Iterator<String> getPocKeys(){
        return Pocs.POCS.keySet().iterator();
    }
    
}
