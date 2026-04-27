package com.facebook.imagepipeline.memory;

import X.k;
import java.util.LinkedList;
import java.util.Queue;

/* JADX INFO: loaded from: classes.dex */
class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f6059a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f6060b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    final Queue f6061c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final boolean f6062d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private int f6063e;

    public b(int i3, int i4, int i5, boolean z3) {
        k.i(i3 > 0);
        k.i(i4 >= 0);
        k.i(i5 >= 0);
        this.f6059a = i3;
        this.f6060b = i4;
        this.f6061c = new LinkedList();
        this.f6063e = i5;
        this.f6062d = z3;
    }

    void a(Object obj) {
        this.f6061c.add(obj);
    }

    public void b() {
        k.i(this.f6063e > 0);
        this.f6063e--;
    }

    public Object c() {
        Object objG = g();
        if (objG != null) {
            this.f6063e++;
        }
        return objG;
    }

    int d() {
        return this.f6061c.size();
    }

    public void e() {
        this.f6063e++;
    }

    public boolean f() {
        return this.f6063e + d() > this.f6060b;
    }

    public Object g() {
        return this.f6061c.poll();
    }

    public void h(Object obj) {
        k.g(obj);
        if (this.f6062d) {
            k.i(this.f6063e > 0);
            this.f6063e--;
            a(obj);
        } else {
            int i3 = this.f6063e;
            if (i3 <= 0) {
                Y.a.o("BUCKET", "Tried to release value %s from an empty bucket!", obj);
            } else {
                this.f6063e = i3 - 1;
                a(obj);
            }
        }
    }
}
