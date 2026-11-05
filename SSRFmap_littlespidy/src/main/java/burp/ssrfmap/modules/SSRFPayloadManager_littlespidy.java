// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.modules;

import burp.ssrfmap.model.SSRFModuleCategory_littlespidy;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class SSRFPayloadManager_littlespidy {
    private static SSRFPayloadManager_littlespidy instance;
    private final List<SSRFPayloadItem_littlespidy> allPayloads;
    private final String rawJson;

    private SSRFPayloadManager_littlespidy() {
        String jsonContent = "";
        List<SSRFPayloadItem_littlespidy> parsedList = new ArrayList<>();
        try (InputStream is = getClass().getResourceAsStream("/payloads_littlespidy.json")) {
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    jsonContent = reader.lines().collect(Collectors.joining("\n"));
                    Type listType = new TypeToken<ArrayList<SSRFPayloadItem_littlespidy>>() {}.getType();
                    parsedList = new Gson().fromJson(jsonContent, listType);
                }
            }
        } catch (Exception e) {
            jsonContent = "[]";
            parsedList = Collections.emptyList();
        }

        this.rawJson = jsonContent;
        this.allPayloads = parsedList != null ? parsedList : Collections.emptyList();
    }

    public static synchronized SSRFPayloadManager_littlespidy getInstance() {
        if (instance == null) {
            instance = new SSRFPayloadManager_littlespidy();
        }
        return instance;
    }

    public List<SSRFPayloadItem_littlespidy> getAllPayloads() {
        return new ArrayList<>(allPayloads);
    }

    public List<SSRFPayloadItem_littlespidy> getAllProtocolPayloads() {
        return allPayloads.stream()
                .filter(item -> item.getCategory() == SSRFModuleCategory_littlespidy.PROTOCOL)
                .collect(Collectors.toList());
    }

    public List<SSRFPayloadItem_littlespidy> getCloudPayloads(String provider) {
        return allPayloads.stream()
                .filter(item -> item.getCategory() == SSRFModuleCategory_littlespidy.CLOUD
                        && item.getModuleName().equalsIgnoreCase(provider))
                .collect(Collectors.toList());
    }

    public List<SSRFPayloadItem_littlespidy> getAllCloudPayloads() {
        return allPayloads.stream()
                .filter(item -> item.getCategory() == SSRFModuleCategory_littlespidy.CLOUD)
                .collect(Collectors.toList());
    }

    public List<SSRFPayloadItem_littlespidy> getServicePayloads(String service) {
        return allPayloads.stream()
                .filter(item -> item.getCategory() == SSRFModuleCategory_littlespidy.SERVICE
                        && item.getModuleName().equalsIgnoreCase(service))
                .collect(Collectors.toList());
    }

    public List<SSRFPayloadItem_littlespidy> getAllServicePayloads() {
        return allPayloads.stream()
                .filter(item -> item.getCategory() == SSRFModuleCategory_littlespidy.SERVICE)
                .collect(Collectors.toList());
    }

    public String getRawJson() {
        return rawJson;
    }
}
