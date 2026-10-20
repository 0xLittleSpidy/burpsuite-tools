// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.gwtmap.parser;

import com.littlespidy.gwtmap.model.GWTMethod;
import com.littlespidy.gwtmap.model.GWTModuleInfo;
import com.littlespidy.gwtmap.model.GWTService;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure Java engine porting all GWT-RPC reverse engineering, service enumeration,
 * method extraction, and wire protocol payload generation from gwtmap.
 *
 * @author littlespidy
 */
public class GWTParser {

    private static final String R_VAR = "[a-zA-Z0-9_.\\$]+";

    public static final Map<String, String> COMPLEX_TYPES = new LinkedHashMap<>();
    static {
        COMPLEX_TYPES.put("STRING", "java.lang.String");
        COMPLEX_TYPES.put("INTEGER", "java.lang.Integer");
        COMPLEX_TYPES.put("DOUBLE", "java.lang.Double");
        COMPLEX_TYPES.put("FLOAT", "java.lang.Float");
        COMPLEX_TYPES.put("BYTE", "java.lang.Byte");
        COMPLEX_TYPES.put("BOOLEAN", "java.lang.Boolean");
        COMPLEX_TYPES.put("SHORT", "java.lang.Short");
        COMPLEX_TYPES.put("CHAR", "java.lang.Char");
        COMPLEX_TYPES.put("LONG", "java.lang.Long");
        COMPLEX_TYPES.put("LIST", "java.util.List");
        COMPLEX_TYPES.put("ARRAY", "java.util.ArrayList");
    }

    public static final Map<String, String> SIMPLE_TYPES = new LinkedHashMap<>();
    static {
        SIMPLE_TYPES.put("I", COMPLEX_TYPES.get("INTEGER"));
        SIMPLE_TYPES.put("D", COMPLEX_TYPES.get("DOUBLE"));
        SIMPLE_TYPES.put("F", COMPLEX_TYPES.get("FLOAT"));
        SIMPLE_TYPES.put("B", COMPLEX_TYPES.get("BYTE"));
        SIMPLE_TYPES.put("Z", COMPLEX_TYPES.get("BOOLEAN"));
        SIMPLE_TYPES.put("S", COMPLEX_TYPES.get("SHORT"));
        SIMPLE_TYPES.put("C", COMPLEX_TYPES.get("CHAR"));
        SIMPLE_TYPES.put("J", COMPLEX_TYPES.get("LONG"));
    }

    private static final Pattern HEX_32_PATTERN = Pattern.compile("([A-Z0-9]{32})");
    private static final Pattern UNFLATTEN_PATTERN = Pattern.compile("unflattenKeylistIntoAnswers\\(.*, ?'([A-Z0-9]{32})'\\);");
    private static final Pattern SELECTING_PERMUTATION_PATTERN = Pattern.compile("='?\"?selectingPermutation'?\"?,");

    private static final Pattern STRONGNAME_PATTERN = Pattern.compile("var \\$strongName ?= ?'([A-Z0-9]{32})';");
    private static final Pattern GWT_VER_PATTERN = Pattern.compile("var \\$gwt_version ?= ?\"([0-9.]+)\";");
    private static final Pattern RPC_VER_PATTERN = Pattern.compile("^(?:[\\t ]*)_\\.(?:(?:k)|(?:version)) ?= ?([5-7]);");
    private static final Pattern RPC_FLAGS_PATTERN = Pattern.compile("^(?:[\\t ]*)?" + R_VAR + " ?= ?([0-2]);");

    private static final Pattern SERVICE_PATTERN = Pattern.compile(R_VAR + "\\.call\\(this, ?" + R_VAR + "\\(\\), ?(?:([^,]+), ?)?([^,]+), ?" + R_VAR + "\\)");

    private static final Pattern METHOD_PATTERN = Pattern.compile("(" + R_VAR + " ?= ?new ?" + R_VAR + "\\(" + R_VAR + ", ?)('?" + R_VAR + "'?), ?('?.*'?)\\);");
    private static final Pattern RMT_SVC_PATTERN_1 = Pattern.compile("^[ \\t]*(?:" + R_VAR + " ?= ?)?(" + R_VAR + ")\\(" + R_VAR + ", ?([^,]+), ?([^,]+)\\);");
    private static final Pattern RMT_SVC_PATTERN_2 = Pattern.compile(R_VAR + " ?= ?\\(.*\\(" + R_VAR + ", ?([^,]+)\\).*, ?.*\\(.*\\).*, ?([^,]+)\\), ?.*\\);");
    private static final Pattern ASSIGNMENT_PATTERN = Pattern.compile("^[ \\t]*(?:var )?([a-zA-Z0-9_.\\$]+) ?= ?(?!=)([^;\\r\\n]+);?");

    public static final int MAX_METHOD_LOOKAHEAD = 80;

    private static final Pattern LIST_OBJECT_PATTERN = Pattern.compile("(java\\.util\\.(?:[A-Za-z]+)?List(?:[0-9/]+)?)<([a-zA-Z0-9./]+)[<>]?(?:(.*[^>]))?>");

    // -- Permutations & Fragments ---------------------------------------------

    public static List<String> extractPermutations(List<String> code, GWTClassifier.CodeType codeType) {
        List<String> permutations = new ArrayList<>();
        if (code == null || code.isEmpty()) return permutations;

        if (codeType == GWTClassifier.CodeType.BOOTSTRAP_CLEAN) {
            for (String line : code) {
                Matcher m = UNFLATTEN_PATTERN.matcher(line);
                if (m.find()) {
                    String hash = m.group(1);
                    if (!permutations.contains(hash)) permutations.add(hash);
                }
                if (permutations.size() >= 5) return permutations;
            }
        } else {
            for (String line : code) {
                if (SELECTING_PERMUTATION_PATTERN.matcher(line).find()) {
                    Matcher m = HEX_32_PATTERN.matcher(line);
                    while (m.find()) {
                        String hash = m.group(1);
                        if (!permutations.contains(hash)) permutations.add(hash);
                    }
                    if (!permutations.isEmpty()) return permutations;
                }
            }
        }

        // Fallback: search for any 32-char hex hashes
        if (permutations.isEmpty()) {
            for (String line : code) {
                if (line.contains(".cache.js")) {
                    Matcher m = HEX_32_PATTERN.matcher(line);
                    while (m.find()) {
                        String hash = m.group(1);
                        if (!permutations.contains(hash)) permutations.add(hash);
                    }
                }
            }
        }

        return permutations;
    }

    public static boolean isFragmented(String code) {
        if (code == null) return false;
        int count = 0;
        int idx = 0;
        while ((idx = code.indexOf("__gwtStartLoadingFragment(", idx)) != -1) {
            count++;
            idx += 26;
            if (count > 1) return true;
        }
        return false;
    }

    // -- Module Info ----------------------------------------------------------

    public static void extractModuleInfo(List<String> code, GWTModuleInfo info) {
        if (code == null || info == null) return;

        for (int i = 0; i < code.size(); i++) {
            String line = code.get(i);

            if ("Unknown".equals(info.getGwtVersion())) {
                Matcher m = GWT_VER_PATTERN.matcher(line);
                if (m.find()) info.setGwtVersion(m.group(1));
            }

            if ("Unknown".equals(info.getActivePermutation())) {
                Matcher m = STRONGNAME_PATTERN.matcher(line);
                if (m.find()) info.setActivePermutation(m.group(1));
            }

            if ("Unknown".equals(info.getRpcVersion()) || "7".equals(info.getRpcVersion())) {
                Matcher m = RPC_VER_PATTERN.matcher(line);
                if (m.find()) {
                    info.setRpcVersion(m.group(1));
                    if (i > 0) {
                        Matcher flagMatcher = RPC_FLAGS_PATTERN.matcher(code.get(i - 1));
                        if (flagMatcher.find()) {
                            info.setRpcFlags(flagMatcher.group(1));
                        }
                    }
                }
            }
        }
    }

    // -- Variable & Parameter Resolution --------------------------------------

    public static boolean isNumber(String value) {
        if (value == null || value.isBlank()) return false;
        try {
            Double.parseDouble(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public static Map<String, String> buildVariableMap(List<String> code) {
        Map<String, String> map = new HashMap<>(code != null ? code.size() / 4 : 16);
        if (code == null) return map;
        for (String line : code) {
            Matcher m = ASSIGNMENT_PATTERN.matcher(line);
            if (m.find()) {
                map.put(m.group(1).trim(), m.group(2).trim());
            }
        }
        return map;
    }

    public static String findValue(List<String> code, Map<String, String> varMap, String value) {
        if (value == null) return "";
        if (varMap != null && varMap.containsKey(value)) {
            return varMap.get(value).trim();
        }
        return value;
    }

    public static String findValue(List<String> code, String value) {
        if (code == null || value == null) return value;
        Pattern valuePattern = Pattern.compile(Pattern.quote(value) + " ?= ?([^=][a-zA-Z0-9\\.'/_)(]*)");
        for (String line : code) {
            Matcher m = valuePattern.matcher(line);
            if (m.find()) {
                return m.group(1).trim();
            }
        }
        return value;
    }

    public static String parseParameter(Map<String, String> varMap, String param) {
        if (param == null) return "";
        param = param.trim();
        if (param.equals("null")) return "null";
        if (param.startsWith("'") && param.endsWith("'")) {
            return param.substring(1, param.length() - 1);
        }
        if (param.startsWith("\"") && param.endsWith("\"")) {
            return param.substring(1, param.length() - 1);
        }
        if (param.startsWith("'")) {
            return param.replace("'", "");
        }
        if (isNumber(param)) {
            return param;
        }
        String resolved = findValue(null, varMap, param);
        return resolved.replace("'", "").replace("\"", "");
    }

    public static String parseParameter(List<String> code, String param) {
        if (param == null) return "";
        param = param.trim();
        if (param.equals("null")) return "null";
        if (param.startsWith("'") && param.endsWith("'")) {
            return param.substring(1, param.length() - 1);
        }
        if (param.startsWith("\"") && param.endsWith("\"")) {
            return param.substring(1, param.length() - 1);
        }
        if (param.startsWith("'")) {
            return param.replace("'", "");
        }
        if (isNumber(param)) {
            return param;
        }
        return findValue(code, param).replace("'", "").replace("\"", "");
    }

    public static int getOffset(List<String> code, int line, String key) {
        if (code == null) return -1;
        int max = Math.min(code.size(), line + MAX_METHOD_LOOKAHEAD);
        for (int i = line; i < max; i++) {
            String check = code.get(i).replace(" ", "");
            if (check.contains(key)) {
                return i - line;
            }
        }
        return -1;
    }

    // -- Service Enumeration --------------------------------------------------

    public static List<GWTService> extractServiceInfo(List<String> code, Map<String, String> varMap) {
        List<GWTService> services = new ArrayList<>();
        if (code == null) return services;

        for (String line : code) {
            Matcher m = SERVICE_PATTERN.matcher(line);
            if (m.find()) {
                String rawPath = m.group(1);
                String rawStrong = m.group(2);

                String servicePath = (rawPath != null && !rawPath.isBlank()) ? parseParameter(varMap, rawPath) : "Unknown";
                String strongName = (rawStrong != null) ? parseParameter(varMap, rawStrong) : "Unknown";

                GWTService service = new GWTService(servicePath, strongName);
                if (!services.contains(service)) {
                    services.add(service);
                }
            }
        }

        services.sort(Comparator.comparing(GWTService::getServicePath));
        return services;
    }

    public static List<GWTService> extractServiceInfo(List<String> code) {
        return extractServiceInfo(code, buildVariableMap(code));
    }

    // -- Method Enumeration ---------------------------------------------------

    public static List<String> extractMethodSignature(List<String> code, Map<String, String> varMap, int line) {
        line += 5;
        List<String> signature = new ArrayList<>();
        if (code == null || line >= code.size()) return signature;

        int offset = getOffset(code, line, "catch(");
        if (offset <= 2) return signature;

        Pattern paramPattern = Pattern.compile(R_VAR + "\\(.*, ?.*, ?(.*)\\)\\);");

        int count = (offset - 2) / 2;
        for (int i = 0; i < count && (line + i) < code.size(); i++) {
            Matcher m = paramPattern.matcher(code.get(line + i));
            String parameter = "UNKNOWN";
            if (m.find()) {
                parameter = parseParameter(varMap, m.group(1));
            }
            if (parameter == null || parameter.isBlank()) {
                parameter = "UNKNOWN";
            }

            if (parameter.startsWith(COMPLEX_TYPES.get("LIST"))) {
                parameter += "<" + COMPLEX_TYPES.get("ARRAY") + "/4159755760<" + COMPLEX_TYPES.get("STRING") + "/2004016611>>";
            } else if (parameter.matches("java\\.util\\.[A-Za-z]+List/.*")) {
                parameter += "<" + COMPLEX_TYPES.get("STRING") + "/2004016611>";
            }

            signature.add(parameter);
        }

        return signature;
    }

    public static List<String> extractMethodSignature(List<String> code, int line) {
        return extractMethodSignature(code, null, line);
    }

    public static GWTService correlateService(GWTMethod method, List<GWTService> services) {
        if (services == null || services.isEmpty() || method == null) return null;

        String[] parts = method.getRmtSvcIntName().toLowerCase().split("\\.");
        String serviceSegment = parts[parts.length - 1];

        for (GWTService s : services) {
            String path = s.getServicePath().toLowerCase().replace("/", "");
            if (serviceSegment.contains(path) || path.contains(serviceSegment)) {
                return s;
            }
        }
        return null;
    }

    public static List<String> normaliseSignature(List<String> methodSignature) {
        Set<String> set = new LinkedHashSet<>(methodSignature);
        List<String> normalised = new ArrayList<>(set);

        for (int i = 0; i < normalised.size(); i++) {
            String sig = normalised.get(i);
            Matcher m = LIST_OBJECT_PATTERN.matcher(sig);
            if (m.matches()) {
                String p1 = m.group(1);
                String p2 = m.group(2);
                String p3 = m.group(3);

                normalised.set(i, p1);
                int ins = 1;
                if (p2 != null && !p2.isBlank()) {
                    normalised.add(i + ins++, p2);
                }
                if (p3 != null && !p3.isBlank()) {
                    normalised.add(i + ins++, p3);
                }
            }
        }

        List<String> result = new ArrayList<>();
        for (String s : normalised) {
            if (s != null && !s.isBlank() && !result.contains(s)) {
                result.add(s);
            }
        }
        return result;
    }

    public static List<String> getMethodParameterValues(List<String> code, int line, List<String> fullSig) {
        List<String> paramList = new ArrayList<>();
        if (code == null) return paramList;

        int rawOffset = getOffset(code, line, "catch(");
        if (rawOffset <= 3) return paramList;

        int offset = rawOffset - 3;
        line += (1 + (offset / 2));

        Pattern paramPattern = Pattern.compile(", ?(?:'' ?\\+ ?)?(?:" + R_VAR + "\\(?.*, ?)?(.*[^\\)])\\)\\)?;");
        Pattern nestedBooleanPattern = Pattern.compile(".*\\?(('?" + R_VAR + "'?):('?" + R_VAR + "'?))");
        Random rand = new Random();

        int count = offset / 2;
        for (int i = 0; i < count && (line + i) < code.size(); i++) {
            String currentLine = code.get(line + i);
            Matcher m = paramPattern.matcher(currentLine);
            String param = "value";
            if (m.find()) {
                param = m.group(1).replace("'", "");
            }

            boolean isBool = nestedBooleanPattern.matcher(currentLine).find()
                    || (i < fullSig.size() && fullSig.get(i).startsWith(COMPLEX_TYPES.get("BOOLEAN")));

            if (isBool) {
                paramList.add("§0§");
            } else if (isNumber(param) || (i < fullSig.size() && fullSig.get(i).startsWith("I"))) {
                paramList.add("§" + (isNumber(param) ? param : String.valueOf(rand.nextInt(100))) + "§");
            } else {
                param = param.replace(" ", "_").replace("|", "\\!").replace("\\", "\\\\");
                paramList.add("§param_" + param + "§");
            }
        }

        return paramList;
    }

    public static Map.Entry<List<String>, List<String>> getStringValues(List<String> paramValues, List<String> fullSignature) {
        List<String> strings = new ArrayList<>();
        List<String> complexTypes = new ArrayList<>();

        for (int i = 0; i < paramValues.size(); i++) {
            String val = paramValues.get(i);
            String sig = (i < fullSignature.size()) ? fullSignature.get(i) : "";

            if (sig.contains(COMPLEX_TYPES.get("STRING"))) {
                strings.add(val);
            } else {
                boolean knownComplex = false;
                for (String cVal : COMPLEX_TYPES.values()) {
                    if (sig.startsWith(cVal)) {
                        knownComplex = true;
                        break;
                    }
                }
                if (!knownComplex && !SIMPLE_TYPES.containsKey(sig)) {
                    if (!complexTypes.contains(sig)) complexTypes.add(sig);
                    strings.add(val);
                }
            }
        }

        return new AbstractMap.SimpleEntry<>(strings, complexTypes);
    }

    public static List<String> generateParameterMap(List<String> rpcBlocks, List<String> fullSignature, List<String> paramValues) {
        List<String> parameterMap = new ArrayList<>();

        // Append type index for each parameter value
        for (int i = 0; i < paramValues.size(); i++) {
            String paramType = (i < fullSignature.size()) ? fullSignature.get(i) : "";
            Matcher m = LIST_OBJECT_PATTERN.matcher(paramType);
            if (m.matches()) {
                String listType = m.group(1);
                int idx = rpcBlocks.indexOf(listType);
                parameterMap.add(String.valueOf(idx >= 0 ? idx - 2 : 1));
            } else {
                int idx = rpcBlocks.indexOf(paramType);
                parameterMap.add(String.valueOf(idx >= 0 ? idx - 2 : 1));
            }
        }

        // For each indexed parameter append type and value indices
        for (int i = 0; i < paramValues.size(); i++) {
            String param = paramValues.get(i);
            String paramType = (i < fullSignature.size()) ? fullSignature.get(i) : "";

            if (paramType.startsWith(COMPLEX_TYPES.get("STRING"))) {
                int idx = rpcBlocks.indexOf(param);
                parameterMap.add(String.valueOf(idx >= 0 ? idx - 2 : 1));
            } else if (SIMPLE_TYPES.containsKey(paramType)) {
                parameterMap.add(param);
            } else {
                Matcher m = LIST_OBJECT_PATTERN.matcher(paramType);
                if (m.matches()) {
                    String listType0 = m.group(1);
                    String listType1 = m.group(2);
                    String listType2 = m.group(3);

                    String targetType = (listType2 == null || listType2.isBlank()) ? listType0 : listType1;
                    int tIdx = rpcBlocks.indexOf(targetType);
                    parameterMap.add(String.valueOf(tIdx >= 0 ? tIdx - 2 : 1));
                    parameterMap.add("1"); // list length = 1

                    String elemType = (listType2 == null || listType2.isBlank()) ? listType1 : listType2;
                    int eIdx = rpcBlocks.indexOf(elemType);
                    parameterMap.add(String.valueOf(eIdx >= 0 ? eIdx - 2 : 1));

                    int vIdx = rpcBlocks.indexOf(param);
                    parameterMap.add(String.valueOf(vIdx >= 0 ? vIdx - 2 : 1));
                } else {
                    int tIdx = rpcBlocks.indexOf(paramType);
                    parameterMap.add(String.valueOf(tIdx >= 0 ? tIdx - 2 : 1));
                    int vIdx = rpcBlocks.indexOf(param);
                    parameterMap.add(String.valueOf(vIdx >= 0 ? vIdx - 2 : 1));
                }
            }
        }

        return parameterMap;
    }

    public static Map.Entry<String, List<String>> buildMethodCall(
            List<String> code,
            int line,
            GWTMethod method,
            GWTModuleInfo moduleInfo) {

        List<String> fullSignature = method.getMethodSignature();
        List<String> normalisedSignature = normaliseSignature(fullSignature);
        List<String> paramValues = getMethodParameterValues(code, line, fullSignature);

        Map.Entry<List<String>, List<String>> strEntry = getStringValues(paramValues, fullSignature);
        List<String> stringValues = strEntry.getKey();
        List<String> complexTypes = strEntry.getValue();

        int rpcPayloadLength = 4 + normalisedSignature.size() + stringValues.size();
        String strongName = (method.getService() != null && !"Unknown".equals(method.getService().getStrongName()))
                ? method.getService().getStrongName()
                : "X".repeat(32);

        List<String> rpcBlocks = new ArrayList<>();
        rpcBlocks.add(moduleInfo.getRpcVersion());
        rpcBlocks.add(moduleInfo.getRpcFlags());
        rpcBlocks.add(String.valueOf(rpcPayloadLength));
        rpcBlocks.add(moduleInfo.getBaseUrl());
        rpcBlocks.add(strongName);
        rpcBlocks.add(method.getRmtSvcIntName());
        rpcBlocks.add(method.getMethodName());

        rpcBlocks.addAll(normalisedSignature);
        rpcBlocks.addAll(stringValues);

        rpcBlocks.add("1");
        rpcBlocks.add("2");
        rpcBlocks.add("3");
        rpcBlocks.add("4");
        rpcBlocks.add(method.getParamCount());

        rpcBlocks.addAll(generateParameterMap(rpcBlocks, fullSignature, paramValues));

        String rpcCall = String.join("|", rpcBlocks) + "|";
        return new AbstractMap.SimpleEntry<>(rpcCall, complexTypes);
    }

    public static List<GWTMethod> extractMethodInfo(List<String> code, List<GWTService> services, GWTModuleInfo moduleInfo, Map<String, String> varMap) {
        List<GWTMethod> methodObjects = new ArrayList<>();
        if (code == null) return methodObjects;

        int methodId = 1;
        for (int loc = 0; loc < code.size(); loc++) {
            String line = code.get(loc);
            Matcher m = METHOD_PATTERN.matcher(line);

            if (m.find() && (loc + 1) < code.size() && code.get(loc + 1).contains("try")) {
                String rawServiceProxy = m.group(2);
                String rawMethodName = m.group(3);

                String rmtSvcIntName = "";
                String paramCount = "0";

                if ((loc + 2) < code.size()) {
                    String line2 = code.get(loc + 2);
                    Matcher rmtM1 = RMT_SVC_PATTERN_1.matcher(line2);
                    if (rmtM1.find()) {
                        rmtSvcIntName = parseParameter(varMap, rmtM1.group(2));
                        paramCount = parseParameter(varMap, rmtM1.group(3));
                    } else {
                        Matcher rmtM2 = RMT_SVC_PATTERN_2.matcher(line2);
                        if (rmtM2.find()) {
                            rmtSvcIntName = parseParameter(varMap, rmtM2.group(1));
                            paramCount = parseParameter(varMap, rmtM2.group(2));
                        }
                    }
                }

                String methodName = parseParameter(varMap, rawMethodName);
                String serviceProxy = parseParameter(varMap, rawServiceProxy);
                List<String> signature = extractMethodSignature(code, varMap, loc - 2);

                GWTMethod method = new GWTMethod(methodId++, methodName, serviceProxy, rmtSvcIntName, paramCount, signature);

                // Correlate with service
                GWTService service = correlateService(method, services);
                method.setService(service);

                // Build RPC call payload
                Map.Entry<String, List<String>> callEntry = buildMethodCall(code, loc + 2, method, moduleInfo);
                method.setMethodRpcCall(callEntry.getKey());
                method.setComplexTypes(callEntry.getValue());

                // Construct full endpoint URL
                String servicePath = (service != null && !service.getServicePath().equals("Unknown"))
                        ? service.getServicePath()
                        : (method.getServiceCategory().substring(0, 1).toLowerCase() + method.getServiceCategory().substring(1));
                if (!servicePath.startsWith("/")) servicePath = "/" + servicePath;

                String base = moduleInfo.getBaseUrl();
                if (base.endsWith("/")) base = base.substring(0, base.length() - 1);
                method.setFullEndpointUrl(base + servicePath);

                methodObjects.add(method);
            }
        }

        // Update method count in services
        for (GWTService s : services) {
            long count = methodObjects.stream().filter(m -> s.equals(m.getService())).count();
            s.setMethodCount((int) count);
        }

        methodObjects.sort(Comparator.comparing(GWTMethod::getServiceProxy).thenComparing(GWTMethod::getMethodName));
        return methodObjects;
    }

    public static List<GWTMethod> extractMethodInfo(List<String> code, List<GWTService> services, GWTModuleInfo moduleInfo) {
        return extractMethodInfo(code, services, moduleInfo, buildVariableMap(code));
    }
}
