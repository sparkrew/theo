# Theo agent

Theo agent creates custom events when sensitive APIs are invoked by the application. 
It uses AspectJ to weave into the sensitive APIs and capture the stack trace, which is then recorded in a Java Flight Recorder (JFR) event.
If the attachment of the java agent is too expensive, we can fall back to using only the default events provided by the JFR.
From Java 25 onwards, JFR will have a new event that enables intercepting custom methods. 
Until it is released, we can use this java agent. 

## Limitations
- If there are any tests that cause timeout exceptions, test execution may fail because the AspectJ weaving slows down the executions.