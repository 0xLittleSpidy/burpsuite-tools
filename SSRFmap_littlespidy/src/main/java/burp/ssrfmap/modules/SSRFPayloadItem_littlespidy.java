// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.modules;

import burp.ssrfmap.model.SSRFModuleCategory_littlespidy;
import java.util.Collections;
import java.util.List;

public class SSRFPayloadItem_littlespidy {
    private final SSRFModuleCategory_littlespidy category;
    private final String moduleName;
    private final String scheme;
    private final String title;
    private final String payloadTemplate;
    private final List<String> expectedIndicators;
    private final boolean requiresCollaborator;

    public SSRFPayloadItem_littlespidy(
            SSRFModuleCategory_littlespidy category,
            String moduleName,
            String scheme,
            String title,
            String payloadTemplate,
            List<String> expectedIndicators,
            boolean requiresCollaborator) {
        this.category = category;
        this.moduleName = moduleName;
        this.scheme = scheme;
        this.title = title;
        this.payloadTemplate = payloadTemplate;
        this.expectedIndicators = expectedIndicators != null ? expectedIndicators : Collections.emptyList();
        this.requiresCollaborator = requiresCollaborator;
    }

    public SSRFModuleCategory_littlespidy getCategory() {
        return category;
    }

    public String getModuleName() {
        return moduleName;
    }

    public String getScheme() {
        return scheme;
    }

    public String getTitle() {
        return title;
    }

    public String getPayloadTemplate() {
        return payloadTemplate;
    }

    public List<String> getExpectedIndicators() {
        return expectedIndicators;
    }

    public boolean isRequiresCollaborator() {
        return requiresCollaborator;
    }
}
