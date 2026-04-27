package io.openinstall.sdk;

import java.lang.Thread;

/* JADX INFO: loaded from: classes3.dex */
class bk implements Thread.UncaughtExceptionHandler {
    final /* synthetic */ bj a;

    bk(bj bjVar) {
        this.a = bjVar;
    }

    @Override // java.lang.Thread.UncaughtExceptionHandler
    public void uncaughtException(Thread thread, Throwable th) {
        if (ec.a) {
            ec.c("Thread " + thread.getName() + " threw exception", th);
        }
    }
}
