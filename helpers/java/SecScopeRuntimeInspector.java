/*
 * SecScope explicit deep-mode Java agent (Java 8 source level).
 *
 * This agent never invokes application methods and never opens a network
 * connection.  It records class-load metadata and the SHA-256 of bytecode
 * supplied by Instrumentation.  It is intentionally premain-only: SecScope
 * does not auto-attach to an already running JVM.  Use solely during an
 * authorized maintenance window with -javaagent:/path/secscope-agent.jar=FILE.
 */
package secscope.runtime;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.security.ProtectionDomain;

public final class SecScopeRuntimeInspector {
    private static PrintWriter output;

    public static void premain(String arguments, final Instrumentation instrumentation) throws Exception {
        if (arguments == null || arguments.length() == 0) throw new IllegalArgumentException("output file argument required");
        File target = new File(arguments).getCanonicalFile();
        File parent = target.getParentFile();
        if (parent == null || !parent.isDirectory()) throw new IllegalArgumentException("existing output directory required");
        output = new PrintWriter(new OutputStreamWriter(new FileOutputStream(target, true), "UTF-8"), true);
        instrumentation.addTransformer(new ClassFileTransformer() {
            public byte[] transform(ClassLoader loader, String name, Class<?> redefining,
                    ProtectionDomain domain, byte[] bytes) {
                writeRecord(name, loader, domain, bytes, redefining != null ? "retransform" : "load");
                return null;
            }
        }, instrumentation.isRetransformClassesSupported());
        for (Class<?> type : instrumentation.getAllLoadedClasses()) {
            ProtectionDomain domain = null;
            try { domain = type.getProtectionDomain(); } catch (Throwable ignored) { }
            writeRecord(type.getName(), type.getClassLoader(), domain, null, "inventory_no_bytes");
        }
        output.println("{\"status\":\"PARTIAL\",\"visibility_gaps\":[\"existing_class_bytecode_hash_requires_explicit_retransform\",\"framework_url_mapping_not_invoked\"]}");
    }

    private static synchronized void writeRecord(String name, ClassLoader loader,
            ProtectionDomain domain, byte[] bytes, String phase) {
        try {
            String source = "";
            if (domain != null) {
                CodeSource codeSource = domain.getCodeSource();
                if (codeSource != null && codeSource.getLocation() != null) source = codeSource.getLocation().toString();
            }
            String loaderName = loader == null ? "bootstrap" : loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader));
            String hash = bytes == null ? "" : sha256(bytes);
            output.println("{\"timestamp_epoch_ms\":" + System.currentTimeMillis() +
                    ",\"phase\":\"" + escape(phase) + "\",\"class_name\":\"" + escape(name) +
                    "\",\"class_loader\":\"" + escape(loaderName) + "\",\"code_source\":\"" +
                    escape(source) + "\",\"bytecode_sha256\":\"" + hash + "\"}");
        } catch (Throwable error) {
            output.println("{\"status\":\"PARTIAL\",\"error\":\"" + escape(error.toString()) + "\"}");
        }
    }

    private static String sha256(byte[] bytes) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
        StringBuilder value = new StringBuilder();
        for (byte item : digest) value.append(String.format("%02x", item & 0xff));
        return value.toString();
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "\\r").replace("\n", "\\n");
    }
}
