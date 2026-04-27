package com.facebook.imagepipeline.producers;

import android.util.Pair;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executor;

/* JADX INFO: loaded from: classes.dex */
public class r0 implements d0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final d0 f6363a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f6364b;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final Executor f6367e;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final ConcurrentLinkedQueue f6366d = new ConcurrentLinkedQueue();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f6365c = 0;

    private class a extends AbstractC0374t {

        /* JADX INFO: renamed from: com.facebook.imagepipeline.producers.r0$a$a, reason: collision with other inner class name */
        class RunnableC0100a implements Runnable {

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            final /* synthetic */ Pair f6369b;

            RunnableC0100a(Pair pair) {
                this.f6369b = pair;
            }

            @Override // java.lang.Runnable
            public void run() {
                r0 r0Var = r0.this;
                Pair pair = this.f6369b;
                r0Var.g((InterfaceC0369n) pair.first, (e0) pair.second);
            }
        }

        private void q() {
            Pair pair;
            synchronized (r0.this) {
                try {
                    pair = (Pair) r0.this.f6366d.poll();
                    if (pair == null) {
                        r0 r0Var = r0.this;
                        r0Var.f6365c--;
                    }
                } catch (Throwable th) {
                    throw th;
                }
            }
            if (pair != null) {
                r0.this.f6367e.execute(new RunnableC0100a(pair));
            }
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        protected void g() {
            p().b();
            q();
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0374t, com.facebook.imagepipeline.producers.AbstractC0358c
        protected void h(Throwable th) {
            p().a(th);
            q();
        }

        @Override // com.facebook.imagepipeline.producers.AbstractC0358c
        protected void i(Object obj, int i3) {
            p().d(obj, i3);
            if (AbstractC0358c.e(i3)) {
                q();
            }
        }

        private a(InterfaceC0369n interfaceC0369n) {
            super(interfaceC0369n);
        }
    }

    public r0(int i3, Executor executor, d0 d0Var) {
        this.f6364b = i3;
        this.f6367e = (Executor) X.k.g(executor);
        this.f6363a = (d0) X.k.g(d0Var);
    }

    @Override // com.facebook.imagepipeline.producers.d0
    public void a(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        boolean z3;
        e0Var.P().g(e0Var, "ThrottlingProducer");
        synchronized (this) {
            try {
                int i3 = this.f6365c;
                z3 = true;
                if (i3 >= this.f6364b) {
                    this.f6366d.add(Pair.create(interfaceC0369n, e0Var));
                } else {
                    this.f6365c = i3 + 1;
                    z3 = false;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (z3) {
            return;
        }
        g(interfaceC0369n, e0Var);
    }

    void g(InterfaceC0369n interfaceC0369n, e0 e0Var) {
        e0Var.P().d(e0Var, "ThrottlingProducer", null);
        this.f6363a.a(new a(interfaceC0369n), e0Var);
    }
}
