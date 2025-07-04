package io.github.chains_project.theo.theo_test_exec.detectorCategories;

import jdk.jfr.consumer.RecordedEvent;

import java.util.Set;

import static io.github.chains_project.theo.theo_commons.PackageMatcher.loadIgnoredPrefixes;

/**
 * This class includes the factory that maps JFR events and creates the detector categories.
 */
public class DetectorCategoryFactory {

    static Set<String> ignoredPrefixes;

    /**
     * Creates a detector category from the observed JFR event.
     *
     * @param event            the event observed JFR
     * @param detectorCategory the name of the observed event
     */
    public static AbstractCategory createCategory(RecordedEvent event, String detectorCategory, String packageName) {
        ignoredPrefixes = loadIgnoredPrefixes(packageName);
        switch ((detectorCategory)) {
            case "Theo" -> {
                String apiCategory = event.getValue("apiCategory");
                String apiSubcategory = event.getValue("apiSubcategory");
                String parameters = event.getValue("parameters");
                return new CustomAPIAccess(apiCategory, apiSubcategory, parameters);
            }
            case "ClassLoad" -> {
                String loadedClass = event.getClass("loadedClass").getName();
                for (String ignore : ignoredPrefixes) {
                    if (loadedClass.startsWith(ignore)) return null;
                }
                return new ClassLoad(loadedClass);
            }
            case "FileWrite" -> {
                String raw = event.getValue("path");
                if (raw == null) {
                    return null;
                }
                // ToDo: update these path checkers in a better way
                if (raw.endsWith(".jar") || raw.startsWith("target/") || raw.startsWith("./target/")) {
                    return null;
                }
                return new FileWrite(raw);
            }
            case "FileRead" -> {
                String raw = event.getValue("path");
                if (raw == null) {
                    return null;
                }
                long bytesRead = event.getValue("bytesRead");
                // ToDo: update these path checkers in a better way
                if (raw.contains(".jar")) {
                    return null;
                }
                return new FileRead(raw, Long.toString(bytesRead));
            }
            case "FileForce" -> {
                String raw = event.getValue("path");
                if (raw == null) {
                    return null;
                }
                boolean metaData = event.getValue("metaData");
                // ToDo: update these path checkers in a better way
                if (raw.contains(".jar")) {
                    return null;
                }
                return new FileForce(raw, Boolean.toString(metaData));
            }
            case "SocketWrite" -> {
                String host = event.getValue("host");
                String address = event.getValue("address");
                int port = event.getValue("port");
                return new SocketWrite(host, address, Integer.toString(port));
            }
            case "SocketRead" -> {
                String host = event.getValue("host");
                String address = event.getValue("address");
                int port = event.getValue("port");
                return new SocketRead(host, address, Integer.toString(port));
            }
            case "NativeLibrary" -> {
                String name = event.getString("name");
                return new NativeLibrary(name);
            }
            case "NetworkUtilization" -> {
                long readRate = event.getValue("readRate");
                long writeRate = event.getValue("writeRate");
                String networkInterface = event.getValue("networkInterface");
                return new NetworkUtilization(Long.toString(readRate),
                        Long.toString(writeRate), networkInterface);
            }
            case "TLSHandshake" -> {
                String peerHost = event.getValue("peerHost");
                int peerPort = event.getValue("peerPort");
                long certificateId = event.getValue("certificateId");
                return new TLSHandshake(peerHost, Integer.toString(peerPort), Long.toString(certificateId));
            }
            case "SecurityPropertyModification" -> {
                String key = event.getValue("key");
                String value = event.getValue("value");
                return new SecurityPropertyModification(key, value);
            }
            case "ThreadStart" -> {
                return new ThreadStart();
            }
            case "ProcessStart" -> {
                String directory = event.getValue("directory");
                String command = event.getValue("command");
                return new ProcessStart(directory, command);
            }
            case "SystemProcess" -> {
                String pid = event.getValue("pid").toString();
                String command = event.getValue("command");
                return new SystemProcess(pid, command);
            }
            case "Deserialization" -> {
                String deserializedClassName = event.getValue("type");
                return new Deserialization(deserializedClassName);
            }
            case "ReservedStackActivation" -> {
                String activatedsensitiveAPI = event.getValue("sensitiveAPI");
                return new ReservedStackActivation(activatedsensitiveAPI);
            }
        }
        return null;
    }

    /**
     * Types of access privileges that the JFR detects.
     */
    public enum DetectionCategory {

        CLASSLOAD("ClassLoad"),
        // Writing data to a file
        FILEWRITE("FileWrite"),
        // Reading data from a file
        FILEREAD("FileRead"),
        // Force updates to be written to file
        FILEFORCE("FileForce"),
        // Writing data to a socket
        SOCKETWRITE("SocketWrite"),
        // Reading data from a socket
        SOCKETREAD("SocketRead"),
        // A native library
        NATIVELIBRARY("NativeLibrary"),
        // Network utilisation
        NETWORKUTILIZATION("NetworkUtilization"),
        // Parameters used in TLS Handshake
        TLSHANDSHAKE("TLSHandshake"),
        // Modification of Security property
        SECURITYPROPERTYMODIFICATION("SecurityPropertyModification"),
        // Operating system process started
        PROCESSSTART("ProcessStart"),
        // Command line
        SYSTEMPROCESS("SystemProcess"),
        // Results of deserialization and ObjectInputFilter checks
        DESERIALIZATION("Deserialization"),
        // Activation of Reserved Stack Area caused by stack overflow with ReservedStackAccess annotated sensitiveAPI
        // in call stack
        RESERVEDSTACKACTIVATION("ReservedStackActivation");

        private final String name;

        DetectionCategory(String s) {
            name = s;
        }

        @Override
        public String toString() {
            return this.name;
        }
    }
}
