package com.facebook.react.fabric;

import java.util.PriorityQueue;
import java.util.Queue;
import k2.AbstractC0605a;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Queue f6956a = new PriorityQueue(11);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Queue f6957b = new PriorityQueue(11, AbstractC0605a.c());

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private double f6958c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f6959d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f6960e;

    public final void a(long j3) {
        if (j3 != 0) {
            if (this.f6956a.size() == this.f6957b.size()) {
                this.f6957b.offer(Long.valueOf(j3));
                this.f6956a.offer(this.f6957b.poll());
            } else {
                this.f6956a.offer(Long.valueOf(j3));
                this.f6957b.offer(this.f6956a.poll());
            }
        }
        int i3 = this.f6959d;
        int i4 = i3 + 1;
        this.f6959d = i4;
        if (i4 == 1) {
            this.f6958c = j3;
        } else {
            this.f6958c = (this.f6958c / ((double) (i4 / i3))) + (j3 / ((long) i4));
        }
        long j4 = this.f6960e;
        if (j3 <= j4) {
            j3 = j4;
        }
        this.f6960e = j3;
    }

    public final double b() {
        return this.f6958c;
    }

    public final long c() {
        return this.f6960e;
    }

    public final double d() {
        long jLongValue;
        Long lValueOf;
        if (this.f6956a.size() == 0 && this.f6957b.size() == 0) {
            return 0.0d;
        }
        if (this.f6956a.size() > this.f6957b.size()) {
            lValueOf = (Long) this.f6956a.peek();
        } else {
            Long l3 = (Long) this.f6956a.peek();
            if (l3 != null) {
                jLongValue = l3.longValue();
            } else {
                Object objPeek = this.f6957b.peek();
                j.c(objPeek);
                jLongValue = ((Number) objPeek).longValue();
            }
            lValueOf = Long.valueOf(jLongValue / ((long) 2));
        }
        return lValueOf.longValue();
    }
}
