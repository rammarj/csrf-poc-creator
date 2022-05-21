
package burp;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 * Implementation of IParameter interface.
 *
 * @author Joaquin R. Martinez <joaquin.ramirez.mtz.lab@gmail.com>
 */
public class Parameter implements IParameter, Cloneable {

    private String name;
    protected String value;
    protected Type type;

    /** Sets the name of this parameter.
     * @param name the name of the parameter.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Sets the value of this parameter.
     * @param value the value of thos parameter.
     */
    public void setValue(String value) {
        this.value = value;
    }

    /**
     * Types of parameters.
     */
    enum Type {
        PARAM_URL, PARAM_HEADER, PARAM_MULTIPART,
        PARAM_FORM_URL_ENCODED, PARAM_UNKNOWN
    }

    /**
     * Constructs a new parameter with its given name, value and type.
     * @param name the name of the parameter.
     * @param value the value of the parameter.
     * @param type the type of the parameter.
     */
    public Parameter(String name, String value, Type type) {
        this.name = name.trim();
        this.value = value.trim();
        this.type = type;
    }

    /**
     * Constructs a new parameter with empty name, value and PARAM_URL as its type.
     */
    public Parameter() {
        this.name = "";
        this.value = "";
        this.type = Type.PARAM_URL;
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
    
    /**
     * Gets the parameter type.
     * @return the type of the parameter.
     */
    public Type getParameterType() {
        return this.type;
    }

    /** Gets the name of this parameter.
     * @return the name of the parameter.
     */
    @Override
    public String getName() {
        return this.name;
    }

    /**
     * Gets the value of this parameter.
     * @return the value of this parameter.
     */
    @Override
    public String getValue() {
        return this.value;
    }

    /**
     * Gets the index where the name stars.
     * @return the index where the name starts.
     */
    @Override
    public int getNameStart() {
        return toString().indexOf(this.name);
    }

    /**
     * Gets the index where the name ends.
     * @return the index where the name ends.
     */
    @Override
    public int getNameEnd() {
        return getNameStart() + this.name.length();
    }

    /**
     * Gets the index where the value starts.
     * @return index where the value starts.
     */
    @Override
    public int getValueStart() {
        return toString().indexOf(this.getValue());
    }

    /**
     * Gets the index where the value ends.
     * @return the index where the value ends.
     */
    @Override
    public int getValueEnd() {
        return getValueStart() + this.value.length();
    }

    /**
     * Gets a string representation of this parameter.
     */
    @Override
    public String toString() {
        StringBuilder a = new StringBuilder();
        if (null == type) 
            a.append(getName()).append("=").append(getValue()).toString();
       else switch (type) {
            case PARAM_MULTIPART:
                a.append("Content-Disposition: form-data; name=\"")
                        .append(this.getName()).append("\"\r\n")
                        .append("\r\n").append(getValue()).append("\r\n");
                break;
            case PARAM_FORM_URL_ENCODED:
            case PARAM_URL:
                try {
                    a.append(getName()).append("=").append(URLEncoder.encode(getValue(), "UTF-8"));
                } catch (UnsupportedEncodingException ex) {}
                break;
            case PARAM_HEADER:
                a.append(getName()).append(": ").append(getValue());
                break;
            default:
                a.append(getName()).append("=").append(getValue()).toString();
                break;
        }
        return a.toString();
    }

    /**
     * Constructs a parameter from a string.
     * @param t the parameter as a string.
     * @return a {@link Parameter} object.
     */
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
