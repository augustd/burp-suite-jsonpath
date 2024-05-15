package burp;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * Formats compressed JSON into pretty-print and stores it into a <tt>List</tt> of individual lines which can be used to populate the clickable UI.
 * 
 * @author August Detlefsen, based on com.jayway.jsonpath.internal.JsonFormatter
 */
public class JsonFormatter {

    private static final String INDENT = "   ";

    private static final String NEW_LINE = System.getProperty("line.separator");

    private static final int MODE_SINGLE = 100;
    private static final int MODE_DOUBLE = 101;
    private static final int MODE_ESCAPE_SINGLE = 102;
    private static final int MODE_ESCAPE_DOUBLE = 103;
    private static final int MODE_BETWEEN = 104;

    private final String formattedJson;
    private final List<PathTuple> lines = new ArrayList<>();
    private final ArrayDeque<String> tempPath = new ArrayDeque<>();
    private int depth = 0;

    public JsonFormatter(String json) {
        this.formattedJson = parse(json);
    }

    public class PathTuple {

        private String line;
        private String path;

        public PathTuple(String line, String path) {
            this.line = line;
            this.path = path;
        }

		public String getLine() {
			return line;
		}

		public String getPath() {
			return path;
		}

        @Override
        public String toString() {
            return line;
        }
    }

    public String prettyPrint() {
        return formattedJson;
    }

    public List<PathTuple> getLines() {
        return lines;
    }

    private void indent() {
        System.out.println("indent");
        ++depth;
        tempPath.push("");
    }

    private void outdent() {
        System.out.println("outdent");
        --depth;
        tempPath.pop();
    }

    private void appendIndent(StringBuilder sb, int count) {
        for (int i = 0; i < count; i++) {
            sb.append(INDENT);
        }
    }

    private void newLine(StringBuilder sb, StringBuilder currLine) {
        //add to pretty print output
        sb.append(currLine).append(NEW_LINE);

        //does this line have an identifier? 
        String line = currLine.toString();
        String[] parts = line.split(":", 2);
        PathTuple path = new PathTuple(currLine.toString(), null);
        if (parts.length == 2) {
            //this is a name-value pair e.g. "id" : "6",
            //get the name to add to our JSONPath
            String name = stripQuotes(parts[0]);
            if (parts[1].contains("[")) {
                name += "[*]";
            }
            pathReplace(name);
            path.path = getPath();
        } else if (line.contains("[")) {
            //we've started an array
            pathReplace("[*]");
        }
        lines.add(path);
        currLine.setLength(0);
    }

    private void pathReplace(String newValue) {
        System.out.println("pathReplace: " + newValue);
        if (tempPath.size() > 0) {
            tempPath.pop();
        }

        tempPath.push(newValue);
    }

    private String getPath() {
        StringBuilder output = new StringBuilder(64);
        output.append("$");
        Iterator<String> i = tempPath.descendingIterator();
        while (i.hasNext()) { // (String element : ) {
            String next = i.next();
            System.out.println("next: " + next);
            if (!next.startsWith("[") && !"".equals(next)) {
                output.append(".");
            }
            if (next.contains(".")) {
                next = "['" + next + "']";
            }
            output.append(next);
        }
        System.out.println("getPath: " + output.toString());
        return output.toString();
    }

    private String stripQuotes(String input) {
        String output = input.trim();
        output = output.replace("\"", "");
        output = output.replace("'", "");
        return output;
    }

    private String parse(String input) {

        input = input.replaceAll("[\\r\\n]", "");

        StringBuilder output = new StringBuilder(input.length() * 2);
        StringBuilder currLine = new StringBuilder(64);
        int mode = MODE_BETWEEN;

        for (int i = 0; i < input.length(); ++i) {
            char ch = input.charAt(i);

            switch (mode) {
                case MODE_BETWEEN:
                    switch (ch) {
                        case '{':
                        case '[':
                            currLine.append(ch);
                            newLine(output, currLine);
                            indent();
                            appendIndent(currLine, depth);
                            break;
                        case '}':
                        case ']':
                            newLine(output, currLine);
                            outdent();
                            appendIndent(currLine, depth);
                            currLine.append(ch);
                            break;
                        case ',':
                            currLine.append(ch);
                            newLine(output, currLine);
                            appendIndent(currLine, depth);
                            break;
                        case ':':
                            currLine.append(" : ");
                            break;
                        case '\'':
                            currLine.append(ch);
                            mode = MODE_SINGLE;
                            break;
                        case '"':
                            currLine.append(ch);
                            mode = MODE_DOUBLE;
                            break;
                        case ' ':
                            break;
                        default:
                            currLine.append(ch);
                            break;
                    }
                    break;
                case MODE_ESCAPE_SINGLE:
                    currLine.append(ch);
                    mode = MODE_SINGLE;
                    break;
                case MODE_ESCAPE_DOUBLE:
                    currLine.append(ch);
                    mode = MODE_DOUBLE;
                    break;
                case MODE_SINGLE:
                    currLine.append(ch);
                    switch (ch) {
                        case '\'':
                            mode = MODE_BETWEEN;
                            break;
                        case '\\':
                            mode = MODE_ESCAPE_SINGLE;
                            break;
                    }
                    break;
                case MODE_DOUBLE:
                    currLine.append(ch);
                    switch (ch) {
                        case '"':
                            mode = MODE_BETWEEN;
                            break;
                        case '\\':
                            mode = MODE_ESCAPE_DOUBLE;
                            break;
                    }
                    break;
            }
        }
        //get the last bits
        output.append(currLine);
        lines.add(new PathTuple(currLine.toString(), null));

        return output.toString();
    }
}
