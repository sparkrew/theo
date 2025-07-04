package io.github.chains_project.theo.theo_agent.agent;

import io.github.chains_project.theo.theo_agent.events.SensitiveAPIAccess;
import io.github.chains_project.theo.theo_commons.SensitiveAPIDescriptor;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.ConstructorSignature;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;

import java.util.Arrays;

@Aspect
public class SensitiveApiAspect {

    private static final Logger log = org.slf4j.LoggerFactory.getLogger(SensitiveApiAspect.class);

    @Pointcut("call(* java.net.URI.*(..))")
    public void netURICalls() {
    }

    @Pointcut("call(* java.net.HttpsURLConnection.*(..))")
    public void netHTTPsConCalls() {
    }

    @Pointcut("call(* java.net.HttpURLConnection.*(..))")
    public void netHTTPConCalls() {
    }

    @Pointcut("call(* java.net.http..*(..))")
    public void netHTTPCalls() {
    }

    @Pointcut("call(* java.net.JarURLConnection.*(..))")
    public void netJarCalls() {
    }

    @Pointcut("call(* java.net.URLDecoder.*(..))")
    public void netDecCalls() {
    }

    @Pointcut("call(* java.net.URLEncoder.*(..))")
    public void netEncCalls() {
    }

    @Pointcut("call(* javax.net.ssl.HttpsURLConnection.*(..))")
    public void javaxNetCalls() {
    }

    @Pointcut("call(* java.util.Properties.*(..))")
    public void propertyCalls() {
    }

    @Pointcut("call(* javax.crypto..*(..))")
    public void cryptoCalls() {
    }

    @Pointcut("call(* javax.sql..*(..))")
    public void javaxSqlCalls() {
    }

    @Pointcut("call(* java.sql..*(..))")
    public void javaSqlCalls() {
    }

    @Pointcut("call(* javax.servlet.http..*(..))")
    public void javaxServletCalls() {
    }

    @Pointcut("call(* jakarta.servlet..*(..))")
    public void jakartaServletCalls() {
    }

    @Pointcut("call(* javax.security.auth..*(..))")
    public void javaxSecurityCalls() {
    }

    @Pointcut("call(* java.nio.channels..*(..))")
    public void nioChannelsCalls() {
    }

    @Pointcut("call(* java.rmi.server..*(..))")
    public void rmiCalls() {
    }

    @Pointcut("call(* java.nio.charset..*(..))")
    public void charsetCalls() {
    }

    @Pointcut("call(* java.util.Base64..*(..))")
    public void base64Calls() {
    }

    @Pointcut("call(* javax.websocket.Decoder..*(..))")
    public void websocketCalls() {
    }

    @Pointcut("call(* java.beans.PropertyDescriptor.*(..))")
    public void beansCalls() {
    }

    @Pointcut("call(* java.util.ServiceLoader.*(..))")
    public void serviceLoaderCalls() {
    }

    @Pointcut("call(* javax.script..*(..))")
    public void scriptCalls() {
    }

    @Pointcut(" netURICalls() || " +
            "netHTTPsConCalls() || " +
            "netHTTPConCalls() || " +
            "netHTTPCalls() || " +
            "netJarCalls() || " +
            "netDecCalls() || " +
            "netEncCalls() || " +
            "javaxNetCalls() || " +
            "propertyCalls() || " +
            "cryptoCalls() || " +
            "javaxSqlCalls() || " +
            "javaSqlCalls() || " +
            "javaxServletCalls() || " +
            "jakartaServletCalls() || " +
            "javaxSecurityCalls() || " +
            "nioChannelsCalls() || " +
            "rmiCalls() || " +
            "charsetCalls() || " +
            "base64Calls() ||" +
            "websocketCalls() ||" +
            "beansCalls() ||" +
            "serviceLoaderCalls() ||" +
            "scriptCalls()")
    public void sensitiveCalls() {
    }

    @Around("sensitiveCalls()")
    public Object traceSensitiveApiCalls(ProceedingJoinPoint joinPoint) throws Throwable {
        String className = joinPoint.getSignature().getDeclaringTypeName();
        String methodName = getMethodName(joinPoint);
        SensitiveApiRegistry.initialize();
//        log.info("[SENSITIVE-API] Intercepting call to: " + className + "." + methodName);
        SensitiveAPIDescriptor sensitiveApi = SensitiveApiRegistry.findSensitiveApi(className, methodName);
        if (sensitiveApi == null) {
            return joinPoint.proceed();
        }
        return recordSensitiveApiCall(joinPoint, sensitiveApi);
    }

    private Object recordSensitiveApiCall(ProceedingJoinPoint joinPoint, SensitiveAPIDescriptor sensitiveApi) throws Throwable {
        SensitiveAPIAccess event = new SensitiveAPIAccess();
        event.className = sensitiveApi.className();
        event.methodName = sensitiveApi.method();
        event.apiCategory = sensitiveApi.category();
        event.apiSubcategory = sensitiveApi.subcategory();
        try {
            Object[] args = joinPoint.getArgs();
            event.parameters = args != null ? Arrays.toString(args) : "[]";
        } catch (Exception e) {
            event.parameters = "[Error getting parameters: " + e.getMessage() + "]";
        }
        event.begin();
        try {
            return joinPoint.proceed();
        } catch (Throwable t) {
            throw t;
        } finally {
            event.end();
            event.commit();
            //logSensitiveApiCall(sensitiveApi, event.parameters);
        }
    }

    private String getMethodName(ProceedingJoinPoint joinPoint) {
        if (joinPoint.getSignature() instanceof ConstructorSignature) {
            return "<clinit>";
        } else if (joinPoint.getSignature() instanceof MethodSignature) {
            return joinPoint.getSignature().getName();
        }
        return joinPoint.getSignature().getName();
    }

    private void logSensitiveApiCall(SensitiveAPIDescriptor api, String params) {
        log.info("[SENSITIVE-API] {}/{}: {}.{}({})",
                api.category(),
                api.subcategory(),
                api.className(),
                api.method(),
                params
        );
    }
}