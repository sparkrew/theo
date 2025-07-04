package io.github.chains_project.theo.theo_test_exec.utils;

public record FrameInfo(String methodName, String dependency) {

    @Override
    public String toString() {
        return ("Frame{methodName = %s, dependency = %s,}")
                .formatted(methodName, dependency);
    }

}
