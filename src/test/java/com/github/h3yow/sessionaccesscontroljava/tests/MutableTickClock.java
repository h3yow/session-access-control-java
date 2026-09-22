package com.github.h3yow.sessionaccesscontroljava.tests;

import com.github.h3yow.sessionaccesscontroljava.clock.TickClock;

import java.time.Instant;

/** 可控时钟：测试可手动推进时间以验证过期语义。 */
public class MutableTickClock implements TickClock {

    private volatile Instant now;

    public MutableTickClock(Instant start) {
        this.now = start;
    }

    @Override
    public Instant now() {
        return now;
    }

    public void set(Instant instant) {
        this.now = instant;
    }

    public void advanceSeconds(long seconds) {
        this.now = now.plusSeconds(seconds);
    }

    public void advance(java.time.Duration duration) {
        this.now = now.plus(duration);
    }
}
