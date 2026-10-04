package com.github.h3yow.sessionaccesscontroljava.tests;

import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 业务覆盖日志扩展：
 * - 每个测试类开始时打印"业务模块"横幅（取类上的 @DisplayName，没有则用类名）；
 * - 每个用例开始/结束打印业务用例名称与通过情况（✅/❌，失败附原因）；
 * - 每个类结束时汇总用例数与通过数。
 * 通过 src/test/resources/junit-platform.properties 全局自动注册，对既有用例同样生效。
 */
public class BusinessCoverageLoggingExtension
        implements BeforeAllCallback, BeforeEachCallback, AfterEachCallback, AfterAllCallback {

    private static final String PASSED_KEY = "passed";
    private static final String TOTAL_KEY = "total";

    private Logger logger(ExtensionContext context) {
        return LoggerFactory.getLogger(context.getRequiredTestClass());
    }

    private String businessModule(ExtensionContext context) {
        var display = context.getRequiredTestClass().getAnnotation(org.junit.jupiter.api.DisplayName.class);
        return display != null ? display.value() : context.getRequiredTestClass().getSimpleName();
    }

    private String caseName(ExtensionContext context) {
        return context.getDisplayName();
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        logger(context).info("");
        logger(context).info("================ 业务模块: {} ================", businessModule(context));
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.GLOBAL);
        store.put(TOTAL_KEY, new int[]{0});
        store.put(PASSED_KEY, new int[]{0});
    }

    @Override
    public void beforeEach(ExtensionContext context) {
        int[] counter = context.getStore(ExtensionContext.Namespace.GLOBAL).get(TOTAL_KEY, int[].class);
        counter[0]++;
        logger(context).info("[用例开始] {}", caseName(context));
    }

    @Override
    public void afterEach(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.GLOBAL);
        boolean passed = context.getExecutionException().isEmpty();
        if (passed) {
            store.get(PASSED_KEY, int[].class)[0]++;
            logger(context).info("[用例通过] ✅ {}", caseName(context));
        } else {
            Throwable t = context.getExecutionException().orElse(new AssertionError("unknown"));
            logger(context).error("[用例失败] ❌ {} 原因: {}", caseName(context), t.toString());
        }
    }

    @Override
    public void afterAll(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.GLOBAL);
        int total = store.get(TOTAL_KEY, int[].class)[0];
        int passed = store.get(PASSED_KEY, int[].class)[0];
        logger(context).info("模块小结 [{}]: 用例 {} 个，通过 {} 个，失败 {} 个",
                businessModule(context), total, passed, total - passed);
        logger(context).info("===============================================================");
    }
}
