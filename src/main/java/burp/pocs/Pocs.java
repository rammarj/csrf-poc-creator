
package burp.pocs;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import burp.IExtensionHelpers;

/**
 * Contains all types of PoC's supported by this plugin.
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Pocs {

	private final Map<String, IPoc> pocs;

	/**
	 * Inaccesible constructor.
	 */
	public Pocs(IExtensionHelpers helpers) {
		this.pocs = new HashMap<>();
		this.pocs.put("Ajax", new AjaxPoc(helpers));
		this.pocs.put("HTML", new HtmlPoc(helpers));
		// Add more kind of PoC's
	}

	/**
	 * Get the {@link IPoc} object by its key.
	 * 
	 * @param key the key of the {@link IPoc}.
	 * @return the {@link IPoc} object.
	 */
	public IPoc getPoc(String key) {
		return pocs.get(key);
	}

	/**
	 * Get the {@link IPoc} as a {@link Enumeration}.
	 * 
	 * @return an {@link Iterator} with the keys of all {@link IPoc} objects.
	 */
	public Iterator<String> getPocKeys() {
		return this.pocs.keySet().iterator();
	}

}
