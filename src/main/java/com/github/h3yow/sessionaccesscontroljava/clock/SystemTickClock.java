package com.github.h3yow.sessionaccesscontroljava.clock;

import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Instant;

/** 统一时间源，测试中可替换为固定/可控时钟。 */
@Component
public class SystemTickClock implements TickClock {
    private final Clock clock = Clock.systemUTC();

    @Override
    public Instant now() {
        return clock.instant();
    }
}
