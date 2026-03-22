package com.alipay.android.phone.mrpc.core;

import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;

/* renamed from: com.alipay.android.phone.mrpc.core.m */
/* loaded from: classes.dex */
public final class C3153m extends FutureTask<C3161u> {

    /* renamed from: a */
    public final /* synthetic */ CallableC3157q f8564a;

    /* renamed from: b */
    public final /* synthetic */ C3152l f8565b;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3153m(C3152l c3152l, Callable callable, CallableC3157q callableC3157q) {
        super(callable);
        this.f8565b = c3152l;
        this.f8564a = callableC3157q;
    }

    @Override // java.util.concurrent.FutureTask
    public final void done() {
        C3155o m3716a = this.f8564a.m3716a();
        if (m3716a.m3719f() == null) {
            super.done();
            return;
        }
        try {
            get();
            if (isCancelled() || m3716a.m3721h()) {
                m3716a.m3720g();
                if (isCancelled() && isDone()) {
                    return;
                }
                cancel(false);
            }
        } catch (InterruptedException e2) {
            new StringBuilder().append(e2);
        } catch (CancellationException unused) {
            m3716a.m3720g();
        } catch (ExecutionException e3) {
            if (e3.getCause() == null || !(e3.getCause() instanceof HttpException)) {
                new StringBuilder().append(e3);
                return;
            }
            HttpException httpException = (HttpException) e3.getCause();
            httpException.getCode();
            httpException.getMsg();
        } catch (Throwable th) {
            throw new RuntimeException("An error occured while executing http request", th);
        }
    }
}
