package io.github.chains_project.theo.monitor.detectorCategories;

import jdk.jfr.consumer.RecordedEvent;

import java.util.List;

/**
 * This class includes the factory that maps JFR events and creates the detector categories.
 */
public class DetectorCategoryFactory {

    /**
     * Creates a detector category from the observed JFR event.
     *
     * @param method           method of the java frame in the stacktrace
     * @param className        classname of the method
     * @param calledBy         the trace of other methods which called the method under consideration
     * @param event            the event observed JFR
     * @param detectorCategory the name of the observed event
     */
    public static AbstractCategory createCategory(String method, String className, List<AbstractCategory.SubMethod>
            calledBy, RecordedEvent event, String detectorCategory) {
        switch ((detectorCategory)) {
//            case "ClassLoad" -> {
//                String loadedClass = event.getClass("loadedClass").getName();
//                String definingClassLoader = event.getValue("definingClassLoader").toString();
//                String initiatingClassLoader = event.getValue("initiatingClassLoader").toString();
//                return new ClassLoad(method, className, calledBy, loadedClass, definingClassLoader,
//                        initiatingClassLoader);
//            }
            case "FileWrite" -> {
                String raw = event.getValue("path");
                if (raw == null) {
                    return null;
                }
                // ToDo: update these path checkers in a better way
                if (raw.endsWith(".jar")) {
                    return null;
                }
                return new FileWrite(method, className, calledBy, raw);
            }
            case "FileRead" -> {
                String raw = event.getValue("path");
                if (raw == null) {
                    return null;
                }
                long bytesRead = event.getValue("bytesRead");
                boolean endOfFile = event.getValue("endOfFile");
                // ToDo: update these path checkers in a better way
                if (raw.contains(".jar")) {
                    return null;
                }
                return new FileRead(method, className, calledBy, raw, Long.toString(bytesRead),
                        Boolean.toString(endOfFile));
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
                return new FileForce(method, className, calledBy, raw, Boolean.toString(metaData));
            }
            case "SocketWrite" -> {
                String host = event.getValue("host");
                String address = event.getValue("address");
                int port = event.getValue("port");
                long bytesWritten = event.getValue("bytesWritten");
                return new SocketWrite(method, className, calledBy, host, address, Integer.toString(port),
                        Long.toString(bytesWritten));
            }
            case "SocketRead" -> {
                String host = event.getValue("host");
                String address = event.getValue("address");
                int port = event.getValue("port");
                long bytesRead = event.getValue("bytesRead");
                boolean endOfStream = event.getValue("endOfStream");
                return new SocketRead(method, className, calledBy, host, address, Integer.toString(port),
                        Long.toString(bytesRead),
                        Boolean.toString(endOfStream));
            }
            case "NativeLibrary" -> {
                String name = event.getString("name");
                return new NativeLibrary(method, className, calledBy, name);
            }
            case "NetworkUtilization" -> {
                long readRate = event.getValue("readRate");
                long writeRate = event.getValue("writeRate");
                String networkInterface = event.getValue("networkInterface");
                return new NetworkUtilization(method, className, calledBy, Long.toString(readRate),
                        Long.toString(writeRate), networkInterface);
            }
            case "TLSHandshake" -> {
                String peerHost = event.getValue("peerHost");
                int peerPort = event.getValue("peerPort");
                long certificateId = event.getValue("certificateId");
                return new TLSHandshake(method, className, calledBy, peerHost, Integer.toString(peerPort),
                        Long.toString(certificateId));
            }
            case "SecurityPropertyModification" -> {
                String key = event.getValue("key");
                String value = event.getValue("value");
                return new SecurityPropertyModification(method, className, calledBy, key, value);
            }
            case "ThreadStart" -> {
                return new ThreadStart(method, className, calledBy);
            }
            case "ProcessStart" -> {
                String directory = event.getValue("directory");
                String command = event.getValue("command");
                return new ProcessStart(method, className, calledBy, directory, command);
            }
            case "SystemProcess" -> {
                String pid = event.getValue("pid").toString();
                String command = event.getValue("command");
                return new SystemProcess(method, className, calledBy, pid, command);
            }
            case "Deserialization" -> {
                String deserializedClassName = event.getValue("type");
                long bytesRead = event.getValue("bytesRead");
                int arrayLength = event.getValue("arrayLength");
                boolean filterConfigured = event.getValue("filterConfigured");
                return new Deserialization(method, className, calledBy, deserializedClassName, Long.toString(bytesRead),
                        Integer.toString(arrayLength),
                        Boolean.toString(filterConfigured));
            }
            case "ReservedStackActivation" -> {
                String activatedMethod = event.getValue("method");
                return new ReservedStackActivation(method, className, calledBy, activatedMethod);
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
        // Activation of Reserved Stack Area caused by stack overflow with ReservedStackAccess annotated method
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
