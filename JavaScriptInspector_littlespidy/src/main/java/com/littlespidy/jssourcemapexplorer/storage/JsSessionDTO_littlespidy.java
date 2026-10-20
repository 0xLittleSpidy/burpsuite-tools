// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.storage;

import com.littlespidy.jssourcemapexplorer.model.*;

import java.util.ArrayList;
import java.util.List;

/**
 * Data transfer objects for persistent storage of JavaScript Inspector state.
 */
public class JsSessionDTO_littlespidy {

    public static class SessionRootDTO {
        public String formatVersion = "1.0";
        public String savedAt;
        public List<JsFileDTO> files = new ArrayList<>();
    }

    public static class JsFileDTO {
        public int id;
        public String url;
        public String host;
        public String path;
        public int statusCode;
        public int contentLength;
        public boolean firstParty;
        public String originLabel;
        public String framework;
        public String passiveMapStatus;
        public String activeProbeStatus;
        public boolean unpacked;
        public String sourceMapLocation;
        public String timestamp;

        // Base64 HTTP Preservation for JS File
        public boolean hasRequest;
        public String requestBase64;
        public String requestHost;
        public int requestPort;
        public boolean requestSecure;

        public boolean hasResponse;
        public String responseBase64;

        // Base64 HTTP Preservation for Source Map
        public boolean hasSourceMapRequest;
        public String sourceMapRequestBase64;
        public String sourceMapRequestHost;
        public int sourceMapRequestPort;
        public boolean sourceMapRequestSecure;

        public boolean hasSourceMapResponse;
        public String sourceMapResponseBase64;

        // Discovered recon findings on raw JS
        public List<DiscoveredSecret> secrets = new ArrayList<>();
        public List<DiscoveredEndpoint> endpoints = new ArrayList<>();
        public List<DiscoveredCloudUrl> cloudUrls = new ArrayList<>();
        public List<DiscoveredDependency> dependencies = new ArrayList<>();
        public List<DiscoveredComment> comments = new ArrayList<>();
        public List<DiscoveredSecurityBypass> securityBypasses = new ArrayList<>();
        public List<DiscoveredGraphQLOperation> graphQLOperations = new ArrayList<>();

        // Unpacked Project data
        public UnpackedProjectDTO unpackedProject;
    }

    public static class UnpackedProjectDTO {
        public String sourceMapUrl;
        public List<UnpackedSourceFile> files = new ArrayList<>();
    }
}
