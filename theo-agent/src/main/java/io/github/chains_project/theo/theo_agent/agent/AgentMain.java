package io.github.chains_project.theo.theo_agent.agent;

import org.aspectj.weaver.loadtime.Agent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.instrument.Instrumentation;

/**
 * Minimal Java agent that works with AspectJ Load-Time Weaving.
 * The actual method interception is handled by SensitiveApiAspect.
 */
public class AgentMain {

    private static final Logger log = LoggerFactory.getLogger(AgentMain.class);

    /**
     * Agent entry point called before main method.
     * This just initializes the registries - AspectJ handles the rest.
     * <p>
     * IMPORTANT: Do NOT reference any AspectJ aspects from this method!
     * AspectJ aspects are not available during premain execution.
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        log.info("Starting Theo Agent with AspectJ Load-Time Weaving...");
        Agent.premain(agentArgs, inst);
        try {
            log.info("Theo Agent initialized successfully");

        } catch (Exception e) {
            log.error("Failed to initialize Theo Agent: {}", e.getMessage(), e);
        }
    }

    /**
     * Alternative entry point for dynamic agent attachment
     */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        log.info("Starting Theo Agent via dynamic attachment...");
        premain(agentArgs, inst);
    }
}