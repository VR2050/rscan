package io.openinstall.sdk;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes3.dex */
public class aq {
    private volatile ar a = null;
    private final CountDownLatch b = new CountDownLatch(1);
    private final LinkedBlockingQueue<Object> c = new LinkedBlockingQueue<>(1);
    private final Object d = new Object();

    public Object a(long j) throws InterruptedException {
        return this.c.poll(j, TimeUnit.SECONDS);
    }

    public void a() {
        if (this.a == null || this.a == ar.a || this.a == ar.b) {
            this.c.offer(this.d);
        }
    }

    public synchronized void a(ar arVar) {
        this.a = arVar;
    }

    public void a(String str, long j) {
        if (this.a == null || this.a == ar.a || this.a == ar.b) {
            this.c.offer(this.d);
            try {
                this.b.await(j, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                if (ec.a) {
                    ec.b("%s awaitInit interrupted", str);
                }
            }
        }
    }

    public boolean b() {
        return this.a == ar.d;
    }

    public boolean c() {
        return this.a == ar.e || this.a == ar.d || this.a == ar.f;
    }

    public synchronized ar d() {
        return this.a;
    }

    public void e() {
        this.b.countDown();
    }
}
