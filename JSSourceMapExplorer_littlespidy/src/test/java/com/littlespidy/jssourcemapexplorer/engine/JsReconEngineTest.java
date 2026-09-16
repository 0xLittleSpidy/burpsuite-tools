// Created with the help of an AI Agent and littlespidy.
package com.littlespidy.jssourcemapexplorer.engine;

import com.littlespidy.jssourcemapexplorer.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class JsReconEngineTest {

    private static final String DUMMY_SLACK_TOKEN = String.join("-", "xoxb", "123456789012", "1234567890123", "4XxXyYzZ1234567890123456");
    private static final String DUMMY_STRIPE_KEY = String.join("_", "sk", "live", "51AbcDefGhiJklMnoPqrStuVwxYz1234567890");

    @Test
    public void testEntropyCalculationAndSuppression() {
        // High entropy string (e.g. AWS secret or random token)
        String randomToken = "vN8xL9pQ2mK5wR7tY4uI1oP3aS6dF8gH0jK2lZ4x";
        double entropy = Entropy.calculate(randomToken);
        assertTrue(entropy >= 3.8, "Random token should have high entropy: " + entropy);
        assertFalse(Entropy.isSuppressed(randomToken));

        // Low entropy / repeated string
        String repeated = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        double lowEntropy = Entropy.calculate(repeated);
        assertTrue(lowEntropy < 2.0, "Repeated string should have low entropy: " + lowEntropy);

        // Documented sample credential suppression
        assertTrue(Entropy.isSuppressed("AKIAIOSFODNN7EXAMPLE"));
        assertTrue(Entropy.isSuppressed("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));

        // Placeholder suppression
        assertTrue(Entropy.isSuppressed("YOUR_API_KEY_HERE"));
        assertTrue(Entropy.isSuppressed("my-super-secret-password"));
        assertTrue(Entropy.isSuppressed("placeholder_token"));
        assertTrue(Entropy.isSuppressed("insert_api_key"));

        // Public key suppression
        assertTrue(Entropy.isSuppressed("pk_test_1234567890abcdefghijklmnop"));

        // 32-character hex hash suppression (MD5 / Git hash / cache hash)
        assertTrue(Entropy.isSuppressed("5d41402abc4b2a76b9719d911017c592"));
    }

    @Test
    public void testFrameworkDetection() {
        // Next.js URL
        var res1 = JsFrameworkDetector.detect("https://example.com/_next/static/chunks/main.js", "");
        assertEquals("Next.js", res1.name());

        // Nuxt.js URL
        var res2 = JsFrameworkDetector.detect("https://example.com/_nuxt/app.js", "");
        assertEquals("Nuxt.js", res2.name());

        // SvelteKit URL
        var res3 = JsFrameworkDetector.detect("https://example.com/_app/immutable/nodes/0.js", "");
        assertEquals("Svelte", res3.name());

        // React Vite Dev server
        var res4 = JsFrameworkDetector.detect("https://example.com/@react-refresh", "");
        assertEquals("React (Vite Dev)", res4.name());
        assertTrue(res4.isDevServer());

        // Body signature Next.js
        String nextBody = "function Page(){return __NEXT_DATA__;}";
        var res5 = JsFrameworkDetector.detect("https://example.com/bundle.js", nextBody);
        assertEquals("Next.js", res5.name());

        // Body signature Vue
        String vueBody = "Vue.component('item', {template: '<div data-v-1234></div>'});";
        var res6 = JsFrameworkDetector.detect("https://example.com/bundle.js", vueBody);
        assertEquals("Vue.js", res6.name());

        // Body signature Angular
        String angularBody = "var ng={'ng-version': '16.0.0'};";
        var res7 = JsFrameworkDetector.detect("https://example.com/bundle.js", angularBody);
        assertEquals("Angular", res7.name());
    }

    @Test
    public void testWebpackChunkExtraction() {
        String baseUrl = "https://example.com/static/js/main.123456.js";
        String script = "f.e=function(e){return \"\"+({1:\"users\",2:\"billing\",3:\"admin\"}[e]||e)+\".chunk.js\"}";

        java.util.Set<String> chunks = WebpackChunkExtractor.extractChunkUrls(baseUrl, script);
        assertNotNull(chunks);
        assertTrue(chunks.size() >= 3, "Should extract at least 3 chunk URLs, found: " + chunks.size());
        assertTrue(chunks.contains("https://example.com/static/js/users.chunk.js"));
        assertTrue(chunks.contains("https://example.com/static/js/billing.chunk.js"));
        assertTrue(chunks.contains("https://example.com/static/js/admin.chunk.js"));
    }

    @Test
    public void testSecretMiningAndSuppression() {
        String script = "const awsKey = \"AKIA1234567890ABCDEF\";\n"
            + "const sampleAwsKey = \"AKIAIOSFODNN7EXAMPLE\";\n"
            + "const fakeKey = \"AKIAXXXXXXXXXXXXXXXX\";\n"
            + "const placeholder = \"YOUR_API_KEY_HERE\";\n"
            + "const slackToken = \"" + DUMMY_SLACK_TOKEN + "\";\n"
            + "const endpoint = \"/api/v2/users/export\";\n"
            + "const s3 = \"https://company-backup.s3.amazonaws.com/data.zip\";\n";

        var result = SecretAndEndpointMiner.mine("https://example.com/app.js", "JS File", script);

        // Secrets verification
        List<DiscoveredSecret> secrets = result.secrets();
        assertFalse(secrets.isEmpty(), "Should discover secrets");

        boolean foundAws = false;
        boolean foundSampleAws = false;
        boolean foundSlack = false;
        boolean foundPlaceholder = false;

        for (DiscoveredSecret sec : secrets) {
            if ("AKIA1234567890ABCDEF".equals(sec.secretValue())) {
                foundAws = true;
                assertEquals("Critical", sec.severity());
                assertTrue(sec.startOffset() >= 0);
                assertTrue(sec.endOffset() > sec.startOffset());
            }
            if ("AKIAIOSFODNN7EXAMPLE".equals(sec.secretValue())) {
                foundSampleAws = true;
            }
            if ("Slack Token".equals(sec.technique())) {
                foundSlack = true;
                assertEquals("Critical", sec.severity());
            }
            if (sec.secretValue().contains("YOUR_API_KEY_HERE")) {
                foundPlaceholder = true;
            }
        }

        assertTrue(foundAws, "Should detect valid AWS key");
        assertFalse(foundSampleAws, "Sample key AKIAIOSFODNN7EXAMPLE should be suppressed by Entropy rules");
        assertTrue(foundSlack, "Should detect Slack token");
        assertFalse(foundPlaceholder, "Placeholder YOUR_API_KEY_HERE should have been suppressed by Entropy rules");

        // Endpoints verification
        boolean foundEp = result.endpoints().stream().anyMatch(e -> "/api/v2/users/export".equals(e.endpoint()));
        assertTrue(foundEp, "Should discover /api/v2/users/export endpoint");

        // Cloud URLs verification
        boolean foundCloud = result.cloudUrls().stream().anyMatch(c -> c.cloudUrl().contains("company-backup.s3.amazonaws.com"));
        assertTrue(foundCloud, "Should discover AWS S3 cloud URL");
    }

    @Test
    public void testSourceMapDataUriDetection() {
        // Base64 data: URI with valid sources array
        String json = "{\"version\":3,\"file\":\"out.js\",\"sources\":[\"src/app.ts\"],\"mappings\":\"AAAA\"}";
        String base64 = java.util.Base64.getEncoder().encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String script = "console.log('hello');\n//# sourceMappingURL=data:application/json;base64," + base64;

        var detection = SourceMapDetector.detect("https://example.com/app.js", script);
        assertTrue(detection.status().isFound(), "Should detect inline Base64 sourcemap");
        assertEquals("INLINE_BASE64", detection.status().name());

        // Unpack inline map
        var unpacked = SourceMapUnpacker.unpack("https://example.com/app.js", detection.sourceMapLocation());
        assertNotNull(unpacked);
        assertEquals(1, unpacked.getTotalFiles());
        assertEquals("src/app.ts", unpacked.getFiles().iterator().next().relativePath());
    }

    @Test
    public void testSourceMapUnpackerPathTraversalProtection() {
        // Source map with path traversal attempting to escape root
        String json = "{\"version\":3,\"file\":\"out.js\",\"sources\":[\"../../../../etc/passwd\",\"safe/component.js\"],\"sourcesContent\":[\"root:x:0:0:::\",\"console.log(1);\"],\"mappings\":\"AAAA\"}";

        var unpacked = SourceMapUnpacker.unpack("https://example.com/app.js", json);
        assertNotNull(unpacked);
        assertEquals(2, unpacked.getTotalFiles());

        for (var file : unpacked.getFiles()) {
            assertFalse(file.relativePath().startsWith("../"), "Paths must not start with ../");
            assertFalse(file.relativePath().contains("/../"), "Paths must not contain /../");
        }
    }

    @Test
    public void testSignaturesCatalogAndCategories() {
        var signatures = SecretAndEndpointMiner.getCuratedSignatures();
        assertNotNull(signatures);
        assertTrue(signatures.size() >= 850, "Must have at least 850 curated signatures, found: " + signatures.size());
        assertNotNull(signatures.get(0).pattern());
        assertFalse(signatures.get(0).pattern().isEmpty());

        var categories = SecretAndEndpointMiner.getAllCategories();
        assertNotNull(categories);
        assertTrue(categories.size() >= 10, "Must have at least 10 categories, found: " + categories.size());
        assertTrue(categories.contains("Cloud Secrets"));
        assertTrue(categories.contains("Payment & Financial Secrets"));
        assertTrue(categories.contains("AI & ML Secrets"));
        assertTrue(categories.contains("Source Control Tokens"));
        assertTrue(categories.contains("SaaS Tokens"));

        var signatureNames = SecretAndEndpointMiner.getAllSignatureNames();
        assertNotNull(signatureNames);
        assertTrue(signatureNames.size() >= 850, "Must have at least 850 signature names, found: " + signatureNames.size());
        assertTrue(signatureNames.contains("AWS Access Key"));
        assertTrue(signatureNames.contains("Stripe Live Secret Key"));
        assertTrue(signatureNames.contains("OpenAI Project Key"));
        assertTrue(signatureNames.contains("Slack Token"));
    }

    @Test
    public void testKeyhacksVerificationEngine() {
        // 1. Slack Token Verification
        DiscoveredSecret slackSecret = new DiscoveredSecret(
            "https://example.com/app.js", "JS File", "SaaS Tokens",
            DUMMY_SLACK_TOKEN,
            "Critical", 4.2, "High [Firm]", "Slack Token", 10, 0, 0, "xoxb-snippet"
        );
        var slackSpec = SecretVerifierService.generateVerification(slackSecret);
        assertNotNull(slackSpec);
        assertTrue(slackSpec.serviceName().toLowerCase().contains("slack"));
        assertTrue(slackSpec.curlCommand().contains(DUMMY_SLACK_TOKEN));
        assertNotNull(slackSpec.validResponseIndicator());
        assertFalse(slackSpec.validResponseIndicator().isBlank());

        // 2. Stripe Secret Verification
        DiscoveredSecret stripeSecret = new DiscoveredSecret(
            "https://example.com/checkout.js", "JS File", "Payment & Financial Secrets",
            DUMMY_STRIPE_KEY,
            "Critical", 4.5, "High [Firm]", "Stripe Live Secret Key", 15, 0, 0, "sk_live-snippet"
        );
        var stripeSpec = SecretVerifierService.generateVerification(stripeSecret);
        assertNotNull(stripeSpec);
        assertTrue(stripeSpec.serviceName().toLowerCase().contains("stripe"));
        assertTrue(stripeSpec.curlCommand().contains(DUMMY_STRIPE_KEY));

        // 3. Fallback Generic Verification
        DiscoveredSecret unknownSecret = new DiscoveredSecret(
            "https://example.com/internal.js", "JS File", "Custom Tokens",
            "custom_secret_value_xyz789",
            "Medium", 3.8, "Low [Tentative]", "Custom Internal Auth", 20, 0, 0, "custom-snippet"
        );
        var fallbackSpec = SecretVerifierService.generateVerification(unknownSecret);
        assertNotNull(fallbackSpec);
        assertTrue(fallbackSpec.serviceName().contains("Generic"));
        assertTrue(fallbackSpec.curlCommand().contains("custom_secret_value_xyz789"));

        // 4. Verification Spec details
        assertNotNull(slackSpec.endpointUrl());
        assertTrue(slackSpec.endpointUrl().contains("slack.com"));
        assertEquals("POST", slackSpec.httpMethod());
        assertNotNull(slackSpec.validResponseIndicator());
    }

    @Test
    public void testDiverseKeyhacksProviders() {
        // AWS
        DiscoveredSecret awsSecret = new DiscoveredSecret(
            "https://example.com/app.js", "JS File", "Cloud & Infrastructure Keys",
            "AKIAIOSFODNN7EXAMPLE", "Critical", 4.0, "High [Firm]", "AWS Access Key", 0, 0, 0, ""
        );
        var awsSpec = SecretVerifierService.generateVerification(awsSecret);
        assertTrue(awsSpec.serviceName().toLowerCase().contains("amazon") || awsSpec.serviceName().toLowerCase().contains("aws"));
        assertTrue(awsSpec.curlCommand().contains("AKIAIOSFODNN7EXAMPLE"));

        // GitHub
        DiscoveredSecret ghSecret = new DiscoveredSecret(
            "https://example.com/app.js", "JS File", "SaaS Tokens",
            "ghp_1234567890abcdefghijklmnopqrstuvwxyz", "Critical", 4.1, "High [Firm]", "GitHub Personal Access Token", 0, 0, 0, ""
        );
        var ghSpec = SecretVerifierService.generateVerification(ghSecret);
        assertTrue(ghSpec.serviceName().toLowerCase().contains("github"));
        assertTrue(ghSpec.curlCommand().contains("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));

        // OpenAI
        DiscoveredSecret oaiSecret = new DiscoveredSecret(
            "https://example.com/app.js", "JS File", "AI & ML API Keys",
            "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz", "High", 4.3, "High [Firm]", "OpenAI Project Key", 0, 0, 0, ""
        );
        var oaiSpec = SecretVerifierService.generateVerification(oaiSecret);
        assertTrue(oaiSpec.serviceName().toLowerCase().contains("openai"));
        assertTrue(oaiSpec.curlCommand().contains("sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"));

        // SendGrid
        DiscoveredSecret sgSecret = new DiscoveredSecret(
            "https://example.com/app.js", "JS File", "SaaS Tokens",
            "SG.1234567890abcdef.1234567890abcdefghijklmnopqrstuvwxyz", "High", 4.2, "High [Firm]", "SendGrid API Key", 0, 0, 0, ""
        );
        var sgSpec = SecretVerifierService.generateVerification(sgSecret);
        assertTrue(sgSpec.serviceName().toLowerCase().contains("sendgrid"));
        assertTrue(sgSpec.curlCommand().contains("SG.1234567890abcdef.1234567890abcdefghijklmnopqrstuvwxyz"));
    }

    @Test
    public void testDirectRepeaterVerificationRequestGeneration() {
        // 1. Slack Token
        DiscoveredSecret slackSec = new DiscoveredSecret(
            "https://target.corp/app.js", "JS File", "SaaS Tokens",
            DUMMY_SLACK_TOKEN,
            "Critical", 4.2, "High [Firm]", "Slack Token", 10, 0, 0, ""
        );
        var slackReq = SecretVerifierService.getVerificationRequestDetails(slackSec);
        assertNotNull(slackReq);
        assertEquals("slack.com", slackReq.host());
        assertEquals(443, slackReq.port());
        assertTrue(slackReq.secure());
        assertEquals("POST", slackReq.method());
        assertTrue(slackReq.path().startsWith("/api/auth.test"));
        assertTrue(slackReq.rawRequest().contains("Host: slack.com"));
        assertTrue(slackReq.rawRequest().contains("token=" + DUMMY_SLACK_TOKEN.substring(0, 17)));

        // 2. Stripe Live Key
        DiscoveredSecret stripeSec = new DiscoveredSecret(
            "https://target.corp/checkout.js", "JS File", "Payment & Financial Secrets",
            DUMMY_STRIPE_KEY,
            "Critical", 4.5, "High [Firm]", "Stripe Live Secret Key", 15, 0, 0, ""
        );
        var stripeReq = SecretVerifierService.getVerificationRequestDetails(stripeSec);
        assertNotNull(stripeReq);
        assertEquals("api.stripe.com", stripeReq.host());
        assertEquals(443, stripeReq.port());
        assertTrue(stripeReq.secure());
        assertTrue(stripeReq.rawRequest().contains("Authorization: Basic "));

        // 3. AWS STS
        DiscoveredSecret awsSec = new DiscoveredSecret(
            "https://target.corp/app.js", "JS File", "Cloud & Infrastructure Keys",
            "AKIAIOSFODNN7EXAMPLE", "Critical", 4.0, "High [Firm]", "AWS Access Key", 0, 0, 0, ""
        );
        var awsReq = SecretVerifierService.getVerificationRequestDetails(awsSec);
        assertNotNull(awsReq);
        assertEquals("sts.amazonaws.com", awsReq.host());
        assertEquals(443, awsReq.port());
        assertTrue(awsReq.secure());
        assertEquals("POST", awsReq.method());
        assertTrue(awsReq.body().contains("Action=GetCallerIdentity"));
        assertTrue(awsReq.rawRequest().contains("X-Amz-KeyId: AKIAIOSFODNN7EXAMPLE"));

        // 4. Universal Fallback on Source Location Host
        DiscoveredSecret unknownSec = new DiscoveredSecret(
            "https://internal.company.com/static/vendor.js", "JS File", "Internal Auth",
            "custom_internal_token_9999", "Medium", 3.8, "Low [Tentative]", "Custom Internal Auth", 0, 0, 0, ""
        );
        var fallbackReq = SecretVerifierService.getVerificationRequestDetails(unknownSec);
        assertNotNull(fallbackReq);
        assertEquals("internal.company.com", fallbackReq.host());
        assertEquals(443, fallbackReq.port());
        assertTrue(fallbackReq.secure());
        assertTrue(fallbackReq.rawRequest().contains("Authorization: Bearer custom_internal_token_9999"));

        // Ensure host sanitization prevents malformed DNS hosts across all tests
        assertFalse(slackReq.host().contains("<"));
        assertFalse(slackReq.host().contains("{"));
        assertFalse(stripeReq.host().contains("<"));
        assertFalse(stripeReq.host().contains("{"));
        assertFalse(awsReq.host().contains("<"));
        assertFalse(awsReq.host().contains("{"));
        assertFalse(fallbackReq.host().contains("<"));
        assertFalse(fallbackReq.host().contains("{"));
    }

    @Test
    public void testCommentExtractionAndCategorization() {
        String jsContent = """
            // ----------------------------------------------------
            // TODO: Fix authentication bypass on admin route
            // FIXME: Remove hardcoded debug token before release
            /*
             * Danger: test password is admin123
             */
            <!-- Inline template comment: staging server config -->
            const api = "https://api.example.com";
            // Normal developer remark explaining the function
            //# sourceMappingURL=bundle.js.map
            """;

        var result = SecretAndEndpointMiner.mine("https://example.com/app.js", "JS File", jsContent);
        assertNotNull(result.comments());
        assertFalse(result.comments().isEmpty());

        // Verify sourceMappingURL comment is suppressed
        boolean hasSourceMapComment = result.comments().stream()
            .anyMatch(c -> c.commentText().contains("sourceMappingURL"));
        assertFalse(hasSourceMapComment, "sourceMappingURL comment should be filtered from comments list");

        // Verify categories
        boolean hasTodo = result.comments().stream()
            .anyMatch(c -> "TODO / FIXME".equals(c.category()) && c.commentText().contains("authentication bypass"));
        assertTrue(hasTodo, "Should identify TODO / FIXME comment");

        boolean hasFixme = result.comments().stream()
            .anyMatch(c -> "TODO / FIXME".equals(c.category()) && c.commentText().contains("Remove hardcoded debug token"));
        assertTrue(hasFixme, "Should identify FIXME comment");

        boolean hasCred = result.comments().stream()
            .anyMatch(c -> "Credentials / Auth".equals(c.category()) && c.commentText().contains("password is admin123"));
        assertTrue(hasCred, "Should identify Credentials / Auth comment");

        boolean hasDebug = result.comments().stream()
            .anyMatch(c -> "Debug / Config".equals(c.category()) && c.commentText().contains("staging server config"));
        assertTrue(hasDebug, "Should identify Debug / Config comment");

        boolean hasGeneral = result.comments().stream()
            .anyMatch(c -> "General".equals(c.category()) && c.commentText().contains("Normal developer remark"));
        assertTrue(hasGeneral, "Should identify General comment");

        // Verify comment types
        boolean hasSingle = result.comments().stream().anyMatch(c -> "Single-Line (//)".equals(c.commentType()));
        boolean hasMulti = result.comments().stream().anyMatch(c -> "Multi-Line (/* */)".equals(c.commentType()));
        boolean hasHtml = result.comments().stream().anyMatch(c -> "HTML (<!-- -->)".equals(c.commentType()));
        assertTrue(hasSingle, "Should detect single-line comment");
        assertTrue(hasMulti, "Should detect multi-line comment");
        assertTrue(hasHtml, "Should detect HTML comment");
    }

    @Test
    public void testJsFilesTableModelColumns() {
        var model = new com.littlespidy.jssourcemapexplorer.ui.JsFilesTableModel();
        assertEquals(10, model.getColumnCount());
        for (int i = 0; i < model.getColumnCount(); i++) {
            assertNotEquals("Origin", model.getColumnName(i));
            assertNotEquals("Map Recon (Paths / Keys)", model.getColumnName(i));
            assertNotEquals("JS Recon (Paths / Keys)", model.getColumnName(i));
        }
        assertEquals("Framework", model.getColumnName(1));
        assertEquals("Status", model.getColumnName(2));
    }

    @Test
    public void testSecurityBypassDetection() {
        String js = """
            function renderContent(sanitizer, userParam) {
                // Angular DomSanitizer bypasses
                const trustedHtml = sanitizer.bypassSecurityTrustHtml(userParam);
                const trustedScript = sanitizer.bypassSecurityTrustScript("alert(1)");
                const trustedStyle = sanitizer.bypassSecurityTrustStyle(userParam.style);
                const trustedUrl = sanitizer.bypassSecurityTrustUrl("javascript:evil()");
                const trustedResource = sanitizer.bypassSecurityTrustResourceUrl(userParam.url);

                // React dangerouslySetInnerHTML
                const element = <div dangerouslySetInnerHTML={{ __html: userParam.rawContent }} />;

                // Vue v-html
                const template = '<div v-html="userParam.bio"></div>';

                // Svelte {@html}
                const svelteCode = '{@html userParam.profile}';

                // Trusted Types Passthrough Policy
                const policy = trustedTypes.createPolicy('pass', {
                    createHTML: (s) => s
                });

                // Vanilla DOM sinks
                document.getElementById('output').innerHTML = userParam.htmlData;
                eval(userParam.scriptCode);

                // Safe innerHTML reset should be suppressed
                const clearEl = document.getElementById('reset');
                clearEl.innerHTML = "";
            }
            """;

        var result = SecretAndEndpointMiner.mine("https://example.com/bundle.js", "JS File", js);
        List<DiscoveredSecurityBypass> bypasses = result.securityBypasses();
        assertFalse(bypasses.isEmpty(), "Should discover security bypasses");

        // Verify Angular bypasses
        assertTrue(bypasses.stream().anyMatch(b -> "Angular".equals(b.framework()) && "bypassSecurityTrustHtml".equals(b.method()) && "Critical".equals(b.risk())));
        assertTrue(bypasses.stream().anyMatch(b -> "Angular".equals(b.framework()) && "bypassSecurityTrustScript".equals(b.method()) && "Critical".equals(b.risk())));
        assertTrue(bypasses.stream().anyMatch(b -> "Angular".equals(b.framework()) && "bypassSecurityTrustStyle".equals(b.method()) && "High".equals(b.risk())));
        assertTrue(bypasses.stream().anyMatch(b -> "Angular".equals(b.framework()) && "bypassSecurityTrustUrl".equals(b.method()) && "High".equals(b.risk())));
        assertTrue(bypasses.stream().anyMatch(b -> "Angular".equals(b.framework()) && "bypassSecurityTrustResourceUrl".equals(b.method()) && "Critical".equals(b.risk())));

        // Verify React
        assertTrue(bypasses.stream().anyMatch(b -> "React".equals(b.framework()) && b.method().startsWith("dangerouslySetInnerHTML")));

        // Verify Vue
        assertTrue(bypasses.stream().anyMatch(b -> "Vue".equals(b.framework()) && "v-html".equals(b.method())));

        // Verify Svelte
        assertTrue(bypasses.stream().anyMatch(b -> "Svelte".equals(b.framework()) && "{@html ...}".equals(b.method())));

        // Verify Trusted Types
        assertTrue(bypasses.stream().anyMatch(b -> "Sanitizer / Policy Bypass".equals(b.framework()) && b.method().contains("trustedTypes.createPolicy")));

        // Verify Vanilla DOM sinks
        assertTrue(bypasses.stream().anyMatch(b -> "Vanilla DOM Sink".equals(b.framework()) && "innerHTML assignment".equals(b.method())));
        assertTrue(bypasses.stream().anyMatch(b -> "Vanilla DOM Sink".equals(b.framework()) && "eval()".equals(b.method())));

        // Verify safe innerHTML = "" is NOT reported
        assertFalse(bypasses.stream().anyMatch(b -> b.contextSnippet() != null && b.contextSnippet().contains("clearEl.innerHTML = \"\"")));
    }
}

