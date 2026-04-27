package com.facebook.react.common.futures;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class SimpleSettableFuture implements Future {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final CountDownLatch f6647b = new CountDownLatch(1);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private Object f6648c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private Exception f6649d;

    private final void a() {
        if (this.f6647b.getCount() == 0) {
            throw new RuntimeException("Result has already been set!");
        }
    }

    public final Object b() {
        try {
            return get();
        } catch (InterruptedException e3) {
            throw new RuntimeException(e3);
        } catch (ExecutionException e4) {
            throw new RuntimeException(e4);
        }
    }

    public final void c(Object obj) {
        a();
        this.f6648c = obj;
        this.f6647b.countDown();
    }

    @Override // java.util.concurrent.Future
    public boolean cancel(boolean z3) {
        throw new UnsupportedOperationException();
    }

    public final void d(Exception exc) {
        j.f(exc, "exception");
        a();
        this.f6649d = exc;
        this.f6647b.countDown();
    }

    @Override // java.util.concurrent.Future
    public Object get() throws ExecutionException, InterruptedException {
        this.f6647b.await();
        if (this.f6649d == null) {
            return this.f6648c;
        }
        throw new ExecutionException(this.f6649d);
    }

    @Override // java.util.concurrent.Future
    public boolean isCancelled() {
        return false;
    }

    @Override // java.util.concurrent.Future
    public boolean isDone() {
        return this.f6647b.getCount() == 0;
    }

    @Override // java.util.concurrent.Future
    public Object get(long j3, TimeUnit timeUnit) throws ExecutionException, TimeoutException {
        j.f(timeUnit, "unit");
        if (this.f6647b.await(j3, timeUnit)) {
            if (this.f6649d == null) {
                return this.f6648c;
            }
            throw new ExecutionException(this.f6649d);
        }
        throw new TimeoutException("Timed out waiting for result");
    }
}
