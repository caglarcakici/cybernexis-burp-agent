/*
 * Utility tools: cryptographic hashing and common encode/decode operations.
 * Implemented with the JDK so they work regardless of Burp edition.
 */
package com.cybernexis.agent.tools;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

public final class UtilTools {

    private UtilTools() {
    }

    public static void register(ToolRegistry registry) {
        registry.register(new ToolDescriptor(
                "compute_hash",
                "Hash a string. args: input (required), algorithm (md5|sha1|sha256|sha512, default sha256), encoding_format (hex|base64, default hex).",
                false,
                Schema.object()
                        .prop("input", "string", "Text to hash.")
                        .prop("algorithm", "string", "md5 | sha1 | sha256 | sha512.")
                        .prop("encoding_format", "string", "hex | base64.")
                        .require("input")
                        .build(),
                UtilTools::computeHash));

        registry.register(new ToolDescriptor(
                "encode_decode",
                "Encode or decode a string. args: input (required), operation (encode|decode), scheme (base64|url|hex).",
                false,
                Schema.object()
                        .prop("input", "string", "Text to transform.")
                        .prop("operation", "string", "encode | decode.")
                        .prop("scheme", "string", "base64 | url | hex.")
                        .require("input")
                        .build(),
                UtilTools::encodeDecode));
    }

    private static ToolResult computeHash(Map<String, Object> args, ToolContext ctx) {
        String input = Tools.str(args, "input");
        if (input == null) {
            return ToolResult.error("input is required.");
        }
        String algo = Tools.str(args, "algorithm", "sha256").toLowerCase();
        String encoding = Tools.str(args, "encoding_format", "hex").toLowerCase();
        String jdkAlgo;
        switch (algo) {
            case "md5":
                jdkAlgo = "MD5";
                break;
            case "sha1":
            case "sha-1":
                jdkAlgo = "SHA-1";
                break;
            case "sha512":
            case "sha-512":
                jdkAlgo = "SHA-512";
                break;
            default:
                jdkAlgo = "SHA-256";
                algo = "sha256";
        }
        byte[] digest;
        try {
            digest = MessageDigest.getInstance(jdkAlgo).digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return ToolResult.error("Hash failed: " + e.getMessage());
        }
        String output = encoding.equals("base64")
                ? Base64.getEncoder().encodeToString(digest)
                : toHex(digest);
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("algorithm", algo);
        data.put("encoding", encoding);
        data.put("hash", output);
        return ToolResult.ok(data);
    }

    private static ToolResult encodeDecode(Map<String, Object> args, ToolContext ctx) {
        String input = Tools.str(args, "input");
        if (input == null) {
            return ToolResult.error("input is required.");
        }
        String operation = Tools.str(args, "operation", "encode").toLowerCase();
        String scheme = Tools.str(args, "scheme", "base64").toLowerCase();
        boolean encode = !operation.startsWith("dec");
        String output;
        try {
            switch (scheme) {
                case "url":
                    output = encode
                            ? URLEncoder.encode(input, StandardCharsets.UTF_8.name())
                            : URLDecoder.decode(input, StandardCharsets.UTF_8.name());
                    break;
                case "hex":
                    output = encode
                            ? toHex(input.getBytes(StandardCharsets.UTF_8))
                            : new String(fromHex(input), StandardCharsets.UTF_8);
                    break;
                case "base64":
                default:
                    scheme = "base64";
                    output = encode
                            ? Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8))
                            : new String(Base64.getDecoder().decode(input.trim()), StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            return ToolResult.error(scheme + " " + operation + " failed: " + e.getMessage());
        }
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("operation", encode ? "encode" : "decode");
        data.put("scheme", scheme);
        data.put("output", output);
        return ToolResult.ok(data);
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static byte[] fromHex(String s) {
        String clean = s.trim().replaceAll("\\s+", "");
        int len = clean.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len - 1; i += 2) {
            out[i / 2] = (byte) ((Character.digit(clean.charAt(i), 16) << 4)
                    + Character.digit(clean.charAt(i + 1), 16));
        }
        return out;
    }
}
