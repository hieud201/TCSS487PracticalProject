/**
 * This class helps handle command line arguments
 * @auhor Tin Phu
 */

import java.util.HashMap;
import java.util.Map;
public class CommandLineArgsHandler {
    private final Map<String, String> argsMap;

    public CommandLineArgsHandler(String[] args) {
        argsMap = new HashMap<>();
        parseArgs(args);
    }

    /**
     * Simply parse -tag with a string after it as its value.
     * in special case, for -code, the string array after the tag is its value.
     * @param args
     */
    private void parseArgs(String[] args) {
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("-")) {
                String tag = arg.substring(1); // Remove the "-"
                String value = "";
                if ("code".equals(tag)) {
                    // Handling for -code tag
                    StringBuilder codeValueBuilder = new StringBuilder();
                    while (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                        codeValueBuilder.append(args[i + 1]).append(" ");
                        i++;

                    }
                    value = codeValueBuilder.toString().trim();

                } else if (i + 1 < args.length && !args[i + 1].startsWith("-")) {
                    value = args[i + 1];
                    i++;
                }
                argsMap.put(tag, value);
            }
        }
    }


    @Override
    public String toString() {
        return argsMap.toString();
    }

    public String getValue(String tag) {
        return argsMap.get(tag);
    }

    public boolean hasTag(String tag) {
        return argsMap.containsKey(tag);
    }

}