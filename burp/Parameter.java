
package burp;

import burp.IParameter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Implementation of IParameter interface
 *
 * @author Joaquin R. Martinez
 */
public class Parameter implements IParameter, Cloneable {

    private String name;
    protected String value;
    protected Type type;

    public void setName(String name) {
        this.name = name;
    }

    public void setValue(String value) {
        this.value = value;
    }

    enum Type {
        PARAM_URL, PARAM_HEADER, PARAM_MULTIPART,
        PARAM_FORM_URL_ENCODED, PARAM_UNKNOWN
    }

    public Parameter(String name, String value, Type type) {
        this.name = name.trim();
        this.value = value.trim();
        this.type = type;
    }

    public Parameter() {
        this.name = "";
        this.value = "";
    }

    /**
     * Deprecated
     * Deprecated. Use {@link #getParameterType() } instead.
     * @deprecated
     * @see #getParameterType()
     */
    @Override
    public byte getType() {
        return 0;
    }

    public Type getParameterType() {
        return this.type;
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public String getValue() {
        return this.value;
    }

    @Override
    public int getNameStart() {
        return toString().indexOf(this.name);
    }

    @Override
    public int getNameEnd() {
        return getNameStart() + this.name.length();
    }

    @Override
    public int getValueStart() {
        return toString().indexOf(this.getValue());
    }

    @Override
    public int getValueEnd() {
        return getValueStart() + this.value.length();
    }

    @Override
    public String toString() {
        StringBuffer a = new StringBuffer();
        if (type == Type.PARAM_MULTIPART) 
            a.append("Content-Disposition: form-data; name=\"").append(this.getName()).append("\"\r\n")
                    .append("\r\n").append(getValue()).append("\r\n");
       else if (type == Type.PARAM_FORM_URL_ENCODED | type == Type.PARAM_URL) 
            try {
                a.append(getName()).append("=").append(URLEncoder.encode(getValue(), "UTF-8"));
            } catch (UnsupportedEncodingException ex) {}
        else if (type == Type.PARAM_HEADER)
            a.append(getName()).append(": ").append(getValue());
        else
             a.append(getName()).append("=").append(getValue()).toString();
        return a.toString();
    }

    public static Parameter build(String t){
        Parameter parameter = new Parameter();
        String[] split = t.split("=");
        if (split.length>=2) {
            parameter.setName(split[0]);
            parameter.setValue(split[1]);
        }
        return parameter;
    }
    
}
