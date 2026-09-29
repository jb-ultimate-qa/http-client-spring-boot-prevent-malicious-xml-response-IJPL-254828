package com.example.demo;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Test-only endpoints used to verify the fix for the XXE (XML External Entity)
 * injection in the IntelliJ HTTP Client's DOMParser (YouTrack IJPL-254828).
 *
 * <p>This controller plays the role of a *malicious server*. The victim is the
 * IntelliJ HTTP Client: when an {@code .http} response handler script calls
 * {@code new DOMParser().parseFromString(response.body, "application/xml")} on
 * one of these responses, a vulnerable DOMParser will resolve the external
 * entities embedded here (local file read, out-of-band request, or entity
 * expansion). A fixed DOMParser must NOT resolve them.
 *
 * <p>Everything is kept local and observable:
 * <ul>
 *   <li>The file-read payload points at a canary file this app writes to a temp
 *       dir, containing {@link #CANARY}. Nothing sensitive is ever exposed.</li>
 *   <li>The out-of-band payload points back at {@code /xxe/collect} on this same
 *       app, so an SSRF/OOB hit is logged here rather than leaving the machine.</li>
 * </ul>
 *
 * This is authorized defensive QA: verifying a vendor security fix in a controlled,
 * self-contained setup.
 */
@RestController
@RequestMapping("/xxe")
public class XxeTestController {

    static final String CANARY = "SECRET_CANARY_VALUE_DO_NOT_LEAK";

    @Value("${server.port:8080}")
    private int port;

    private Path canaryFile;
    private final AtomicInteger oobHits = new AtomicInteger();

    @PostConstruct
    void writeCanary() throws IOException {
        canaryFile = Files.createTempFile("xxe-canary-", ".txt");
        Files.writeString(canaryFile, CANARY);
        canaryFile.toFile().deleteOnExit();
        System.out.println("[XXE-TEST] Canary file written to: " + canaryFile.toAbsolutePath());
    }

    /** file:// URI of the canary, formatted for an XML SYSTEM identifier. */
    private String canaryUri() {
        return canaryFile.toUri().toString(); // e.g. file:///C:/Users/.../xxe-canary-123.txt
    }

    /**
     * Test case 1 — classic file-read XXE via an external general entity.
     * Vulnerable: parsed DOM's &lt;value&gt; contains the canary string.
     * Fixed: entity is not resolved (empty / literal / parse error), canary absent.
     */
    @GetMapping(value = "/file-entity", produces = MediaType.APPLICATION_XML_VALUE)
    public String fileEntity() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE root [
                  <!ENTITY xxe SYSTEM "%s">
                ]>
                <root><value>&xxe;</value></root>
                """.formatted(canaryUri());
    }

    /**
     * Test case 2 — out-of-band (SSRF) XXE via an external parameter entity.
     * Vulnerable: the parser fetches /xxe/collect, incrementing the OOB counter.
     * Fixed: no request is made, counter stays put.
     */
    @GetMapping(value = "/external-dtd", produces = MediaType.APPLICATION_XML_VALUE)
    public String externalDtd() {
        String collect = "http://localhost:" + port + "/xxe/collect";
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE root [
                  <!ENTITY % ext SYSTEM "%s">
                  %%ext;
                ]>
                <root><value>ok</value></root>
                """.formatted(collect);
    }

    /**
     * Test case 3 — entity-expansion ("billion laughs") denial-of-service.
     * Vulnerable: parsing expands entities (CPU/memory blow-up on larger depths).
     * Fixed: DTD/entity expansion disabled, parse returns quickly or errors.
     * Kept deliberately small (depth ~5) so a vulnerable IDE degrades but does not hang.
     */
    @GetMapping(value = "/billion-laughs", produces = MediaType.APPLICATION_XML_VALUE)
    public String billionLaughs() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE lolz [
                  <!ENTITY lol "lol">
                  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
                  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
                  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
                  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
                ]>
                <lolz>&lol4;</lolz>
                """;
    }

    /**
     * Test case 4 — benign control. Must parse identically before and after the fix.
     * Confirms the DOMParser still works for legitimate XML (no false positives).
     */
    @GetMapping(value = "/benign", produces = MediaType.APPLICATION_XML_VALUE)
    public String benign() {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <root><value>hello-world</value></root>
                """;
    }

    /** Out-of-band collector: any hit here proves the parser made an external request. */
    @GetMapping("/collect")
    public String collect() {
        int n = oobHits.incrementAndGet();
        System.out.println("[XXE-TEST] !!! OOB/SSRF hit received at /xxe/collect (total=" + n + ") — parser resolved external entity");
        return "collected";
    }

    /** Read the OOB counter to assert whether an out-of-band request fired. */
    @GetMapping(value = "/oob-hits", produces = MediaType.TEXT_PLAIN_VALUE)
    public String oobHits() {
        return String.valueOf(oobHits.get());
    }
}
