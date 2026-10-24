// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.graphqlcop.engine;

import burp.api.montoya.MontoyaApi;
import com.littlespidy.graphqlcop.model.AuditFinding_littlespidy;
import com.littlespidy.graphqlcop.model.AuditProbeType_littlespidy;
import com.littlespidy.graphqlcop.model.HttpLogEntry_littlespidy;

import java.util.List;
import java.util.function.Consumer;

public interface AuditProbe_littlespidy {
    AuditProbeType_littlespidy getType();
    List<AuditFinding_littlespidy> execute(MontoyaApi api, String targetUrl, String customHeaders,
                                          Consumer<HttpLogEntry_littlespidy> logConsumer);
}
