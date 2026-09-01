/*
 * Compiles and runs a Montoya script body at runtime using the JDK compiler.
 * Requires Burp to run on a runtime that includes jdk.compiler (javac); if the
 * compiler is unavailable, compilation throws a clear error. Only run code you
 * (or a model you supervise) authored.
 */
package com.cybernexis.agent.script;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;

import burp.api.montoya.MontoyaApi;

public final class RuntimeJavaCompiler {

    private static final AtomicInteger COUNTER = new AtomicInteger();

    private static final String IMPORTS =
            "import burp.api.montoya.*;\n"
            + "import burp.api.montoya.core.*;\n"
            + "import burp.api.montoya.http.*;\n"
            + "import burp.api.montoya.http.message.*;\n"
            + "import burp.api.montoya.http.message.requests.*;\n"
            + "import burp.api.montoya.http.message.responses.*;\n"
            + "import burp.api.montoya.http.message.params.*;\n"
            + "import burp.api.montoya.scanner.*;\n"
            + "import burp.api.montoya.scanner.audit.issues.*;\n"
            + "import burp.api.montoya.sitemap.*;\n"
            + "import java.util.*;\n";

    private RuntimeJavaCompiler() {
    }

    /**
     * Compile {@code body} (statements ending in a {@code return}) into a
     * UserScript and run it against {@code api}. Returns the script's value.
     *
     * @throws IllegalStateException if no Java compiler is available
     * @throws IOException           on I/O failure
     * @throws ScriptCompilationException if the body fails to compile
     * @throws Exception             if the script throws at runtime
     */
    public static Object compileAndRun(String body, MontoyaApi api) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException(
                    "No Java compiler available in this runtime (jdk.compiler missing). "
                            + "run_custom_script requires Burp to run on a JDK.");
        }

        String className = "Script_" + COUNTER.incrementAndGet();
        String fqcn = "com.cybernexis.agent.script.generated." + className;
        String source = "package com.cybernexis.agent.script.generated;\n"
                + IMPORTS
                + "public class " + className + " implements com.cybernexis.agent.script.UserScript {\n"
                + "  public Object run(burp.api.montoya.MontoyaApi api) throws Exception {\n"
                + body + "\n"
                + "  }\n"
                + "}\n";

        Path work = Files.createTempDirectory("cybernexis-script");
        Path outDir = work.resolve("out");
        Files.createDirectories(outDir);

        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager fm = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
            fm.setLocation(StandardLocation.CLASS_OUTPUT, java.util.Collections.singletonList(outDir.toFile()));
            String classpath = buildClasspath();
            List<String> options = new ArrayList<>(Arrays.asList("-classpath", classpath));

            JavaFileObject sourceObject = new StringSource(fqcn, source);
            JavaCompiler.CompilationTask task = compiler.getTask(
                    null, fm, diagnostics, options, null,
                    java.util.Collections.singletonList(sourceObject));

            boolean success = task.call();
            if (!success) {
                StringBuilder sb = new StringBuilder();
                for (Diagnostic<? extends JavaFileObject> d : diagnostics.getDiagnostics()) {
                    sb.append(d.getKind()).append(": line ").append(d.getLineNumber())
                            .append(": ").append(d.getMessage(null)).append('\n');
                }
                throw new ScriptCompilationException(sb.toString().trim());
            }
        }

        ClassLoader parent = RuntimeJavaCompiler.class.getClassLoader();
        try (URLClassLoader loader = new URLClassLoader(new URL[]{outDir.toUri().toURL()}, parent)) {
            Class<?> clazz = Class.forName(fqcn, true, loader);
            UserScript script = (UserScript) clazz.getDeclaredConstructor().newInstance();
            return script.run(api);
        }
    }

    private static String buildClasspath() {
        Set<String> entries = new LinkedHashSet<>();
        addCodeSource(entries, MontoyaApi.class);
        addCodeSource(entries, UserScript.class);
        String jcp = System.getProperty("java.class.path");
        if (jcp != null && !jcp.isEmpty()) {
            entries.add(jcp);
        }
        return String.join(File.pathSeparator, entries);
    }

    private static void addCodeSource(Set<String> entries, Class<?> type) {
        try {
            URL location = type.getProtectionDomain().getCodeSource().getLocation();
            if (location != null) {
                entries.add(new File(location.toURI()).getAbsolutePath());
            }
        } catch (Exception ignored) {
            // fall back to java.class.path
        }
    }

    /** Thrown when the script body fails to compile; message holds compiler errors. */
    public static final class ScriptCompilationException extends Exception {
        public ScriptCompilationException(String message) {
            super(message);
        }
    }

    private static final class StringSource extends javax.tools.SimpleJavaFileObject {
        private final String code;

        StringSource(String fqcn, String code) {
            super(java.net.URI.create("string:///" + fqcn.replace('.', '/') + ".java"), Kind.SOURCE);
            this.code = code;
        }

        @Override
        public CharSequence getCharContent(boolean ignoreEncodingErrors) {
            return code;
        }
    }
}
