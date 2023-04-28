
package burp.pocs;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Contains all types of PoC's supported by this plugin.
 * 
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Pocs {

	private final Map<String, PocGenerator> pocs;

	/**
	 * Inaccesible constructor.
	 */
	public Pocs() {
		this.pocs = new HashMap<>();
		this.pocs.put("Ajax", new AjaxPoc());
		this.pocs.put("HTML", new HtmlPoc());
		// Add more kind of PoC's
	}

	/**
	 * Get the {@link PocGenerator} object by its key.
	 * 
	 * @param key the key of the {@link PocGenerator}.
	 * @return the {@link PocGenerator} object.
	 */
	public PocGenerator getPoc(String key) {
		return pocs.get(key);
	}

	/**
	 * Get the {@link PocGenerator} as a {@link Enumeration}.
	 * 
	 * @return an {@link Iterator} with the keys of all {@link PocGenerator} objects.
	 */
	public Iterator<String> getPocKeys() {
		return this.pocs.keySet().iterator();
	}

}
