/*
 * Minimal dependency-free JSON parser and writer.
 * Parses into Map<String,Object>/List<Object>/String/Double/Long/Boolean/null,
 * and serializes the same shapes back to JSON text. Kept small on purpose so the
 * extension has no third-party runtime dependencies.
 */
package com.cybernexis.agent.json;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Json {

    private Json() {
    }

    // ---- Public API ---------------------------------------------------------

    public static Object parse(String text) {
        return new Parser(text).parseValue();
    }

    /** Parse and require a JSON object at the top level. Returns empty map on failure. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String text) {
        Object v = parse(text);
        if (v instanceof Map) {
            return (Map<String, Object>) v;
        }
        return new LinkedHashMap<>();
    }

    public static String write(Object value) {
        StringBuilder sb = new StringBuilder();
        writeValue(sb, value);
        return sb.toString();
    }

    public static String writePretty(Object value) {
        StringBuilder sb = new StringBuilder();
        writePretty(sb, value, 0);
        return sb.toString();
    }

    // ---- Typed helpers ------------------------------------------------------

    public static String asString(Object o, String def) {
        return o == null ? def : String.valueOf(o);
    }

    public static boolean asBool(Object o, boolean def) {
        if (o instanceof Boolean) {
            return (Boolean) o;
        }
        if (o instanceof String) {
            return Boolean.parseBoolean((String) o);
        }
        return def;
    }

    public static int asInt(Object o, int def) {
        if (o instanceof Number) {
            return ((Number) o).intValue();
        }
        if (o instanceof String) {
            try {
                return (int) Double.parseDouble((String) o);
            } catch (NumberFormatException ignored) {
            }
        }
        return def;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    public static List<Object> asList(Object o) {
        if (o instanceof List) {
            return (List<Object>) o;
        }
        List<Object> single = new ArrayList<>();
        if (o != null) {
            single.add(o);
        }
        return single;
    }

    /** Coerce a value into a list of strings (accepts a single scalar too). */
    public static List<String> asStringList(Object o) {
        List<String> out = new ArrayList<>();
        if (o == null) {
            return out;
        }
        if (o instanceof List) {
            for (Object item : (List<?>) o) {
                if (item != null) {
                    out.add(String.valueOf(item));
                }
            }
        } else {
            out.add(String.valueOf(o));
        }
        return out;
    }

    // ---- Writer -------------------------------------------------------------

    private static void writeValue(StringBuilder sb, Object v) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof String) {
            writeString(sb, (String) v);
        } else if (v instanceof Boolean || v instanceof Number) {
            sb.append(v.toString());
        } else if (v instanceof Map) {
            writeMap(sb, (Map<?, ?>) v);
        } else if (v instanceof Iterable) {
            writeList(sb, (Iterable<?>) v);
        } else {
            writeString(sb, v.toString());
        }
    }

    private static void writeMap(StringBuilder sb, Map<?, ?> map) {
        sb.append('{');
        boolean first = true;
        for (Map.Entry<?, ?> e : map.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeString(sb, String.valueOf(e.getKey()));
            sb.append(':');
            writeValue(sb, e.getValue());
        }
        sb.append('}');
    }

    private static void writeList(StringBuilder sb, Iterable<?> list) {
        sb.append('[');
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeValue(sb, item);
        }
        sb.append(']');
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }

    private static void writePretty(StringBuilder sb, Object v, int indent) {
        if (v instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) v;
            if (map.isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append("{\n");
            int i = 0;
            for (Map.Entry<?, ?> e : map.entrySet()) {
                indent(sb, indent + 1);
                writeString(sb, String.valueOf(e.getKey()));
                sb.append(": ");
                writePretty(sb, e.getValue(), indent + 1);
                if (++i < map.size()) {
                    sb.append(',');
                }
                sb.append('\n');
            }
            indent(sb, indent);
            sb.append('}');
        } else if (v instanceof Iterable) {
            List<Object> list = asList(v);
            if (list.isEmpty()) {
                sb.append("[]");
                return;
            }
            sb.append("[\n");
            for (int i = 0; i < list.size(); i++) {
                indent(sb, indent + 1);
                writePretty(sb, list.get(i), indent + 1);
                if (i < list.size() - 1) {
                    sb.append(',');
                }
                sb.append('\n');
            }
            indent(sb, indent);
            sb.append(']');
        } else {
            writeValue(sb, v);
        }
    }

    private static void indent(StringBuilder sb, int level) {
        for (int i = 0; i < level; i++) {
            sb.append("  ");
        }
    }

    // ---- Parser -------------------------------------------------------------

    private static final class Parser {
        private final String s;
        private int i;

        Parser(String s) {
            this.s = s == null ? "" : s;
        }

        Object parseValue() {
            skipWs();
            if (i >= s.length()) {
                return null;
            }
            char c = s.charAt(i);
            switch (c) {
                case '{':
                    return parseObj();
                case '[':
                    return parseArr();
                case '"':
                    return parseStr();
                case 't':
                case 'f':
                    return parseBool();
                case 'n':
                    return parseNull();
                default:
                    return parseNum();
            }
        }

        private Map<String, Object> parseObj() {
            Map<String, Object> map = new LinkedHashMap<>();
            i++; // {
            skipWs();
            if (peek() == '}') {
                i++;
                return map;
            }
            while (i < s.length()) {
                skipWs();
                String key = parseStr();
                skipWs();
                if (peek() == ':') {
                    i++;
                }
                Object val = parseValue();
                map.put(key, val);
                skipWs();
                char c = peek();
                if (c == ',') {
                    i++;
                    continue;
                }
                if (c == '}') {
                    i++;
                    break;
                }
                break;
            }
            return map;
        }

        private List<Object> parseArr() {
            List<Object> list = new ArrayList<>();
            i++; // [
            skipWs();
            if (peek() == ']') {
                i++;
                return list;
            }
            while (i < s.length()) {
                Object val = parseValue();
                list.add(val);
                skipWs();
                char c = peek();
                if (c == ',') {
                    i++;
                    continue;
                }
                if (c == ']') {
                    i++;
                    break;
                }
                break;
            }
            return list;
        }

        private String parseStr() {
            StringBuilder sb = new StringBuilder();
            if (peek() != '"') {
                return readBareToken();
            }
            i++; // opening quote
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') {
                    break;
                }
                if (c == '\\' && i < s.length()) {
                    char e = s.charAt(i++);
                    switch (e) {
                        case '"':
                            sb.append('"');
                            break;
                        case '\\':
                            sb.append('\\');
                            break;
                        case '/':
                            sb.append('/');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'u':
                            if (i + 4 <= s.length()) {
                                try {
                                    sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                                } catch (NumberFormatException ignored) {
                                }
                                i += 4;
                            }
                            break;
                        default:
                            sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private String readBareToken() {
            int start = i;
            while (i < s.length() && "\":,{}[] \t\n\r".indexOf(s.charAt(i)) < 0) {
                i++;
            }
            return s.substring(start, i);
        }

        private Object parseBool() {
            if (s.startsWith("true", i)) {
                i += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return Boolean.FALSE;
            }
            i++;
            return Boolean.FALSE;
        }

        private Object parseNull() {
            if (s.startsWith("null", i)) {
                i += 4;
            } else {
                i++;
            }
            return null;
        }

        private Object parseNum() {
            int start = i;
            while (i < s.length() && "-+.eE0123456789".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String num = s.substring(start, i);
            if (num.isEmpty()) {
                i++;
                return null;
            }
            try {
                if (num.contains(".") || num.contains("e") || num.contains("E")) {
                    return Double.parseDouble(num);
                }
                return Long.parseLong(num);
            } catch (NumberFormatException ex) {
                return num;
            }
        }

        private char peek() {
            return i < s.length() ? s.charAt(i) : '\0';
        }

        private void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }
    }
}
