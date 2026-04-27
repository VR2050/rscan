package io.openinstall.sdk;

import java.lang.Thread;

/* JADX INFO: loaded from: classes3.dex */
class dd implements Thread.UncaughtExceptionHandler {
    final /* synthetic */ dc a;

    dd(dc dcVar) {
        this.a = dcVar;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public void uncaughtException(Thread thread, Throwable th) {
        if (ec.a) {
            ec.c("Thread " + thread.getName() + " threw exception", th);
        }
    }
}
