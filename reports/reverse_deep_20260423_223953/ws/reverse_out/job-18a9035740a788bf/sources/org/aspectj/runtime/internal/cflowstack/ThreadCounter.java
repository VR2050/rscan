package org.aspectj.runtime.internal.cflowstack;

/* JADX INFO: loaded from: classes3.dex */
public interface ThreadCounter {
    void dec();

    void inc();

    boolean isNotZero();

    void removeThreadCounter();
}
