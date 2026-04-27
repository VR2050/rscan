package io.openinstall.sdk;

import java.util.concurrent.RejectedExecutionHandler;
import java.util.concurrent.ThreadPoolExecutor;

/* JADX INFO: loaded from: classes3.dex */
class de implements RejectedExecutionHandler {
    de() {
    }

    @Override // java.util.concurrent.RejectedExecutionHandler
    public void rejectedExecution(Runnable runnable, ThreadPoolExecutor threadPoolExecutor) {
        if (ec.a) {
            ec.b("Task rejected by " + threadPoolExecutor.toString(), new Object[0]);
        }
    }
}
