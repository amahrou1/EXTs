package burp.jsendpointfinder;

import java.util.List;

public final class JsonExporter {

    private JsonExporter() {
    }

    public static String toJson(List<EndpointRecord> records) {
        StringBuilder sb = new StringBuilder();
        sb.append("[\n");
        for (int i = 0; i < records.size(); i++) {
            EndpointRecord r = records.get(i);
            sb.append("  {\n");
            sb.append("    \"endpoint\": ").append(escapeJson(r.endpoint())).append(",\n");
            sb.append("    \"source\": ").append(escapeJson(r.sourceUrl())).append(",\n");
            sb.append("    \"status\": ").append(escapeJson(r.status())).append(",\n");
            sb.append("    \"found_at\": ").append(escapeJson(r.foundAtFormatted())).append(",\n");
            sb.append("    \"context\": ").append(escapeJson(r.context())).append("\n");
            sb.append("  }");
            if (i < records.size() - 1) {
                sb.append(",");
            }
            sb.append("\n");
        }
        sb.append("]");
        return sb.toString();
    }

    private static String escapeJson(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
        return sb.toString();
    }
}
