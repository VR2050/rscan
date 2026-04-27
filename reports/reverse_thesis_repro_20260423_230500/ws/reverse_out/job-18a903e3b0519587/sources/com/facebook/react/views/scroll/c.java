package com.facebook.react.views.scroll;

import android.os.SystemClock;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private static final a f7888f = new a(null);

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private float f7891c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private float f7892d;

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private int f7889a = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f7890b = Integer.MIN_VALUE;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private long f7893e = -11;

    private static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public final float a() {
        return this.f7891c;
    }

    public final float b() {
        return this.f7892d;
    }

    public final boolean c(int i3, int i4) {
        long jUptimeMillis = SystemClock.uptimeMillis();
        long j3 = this.f7893e;
        boolean z3 = (jUptimeMillis - j3 <= 10 && this.f7889a == i3 && this.f7890b == i4) ? false : true;
        if (jUptimeMillis - j3 != 0) {
            this.f7891c = (i3 - this.f7889a) / (jUptimeMillis - j3);
            this.f7892d = (i4 - this.f7890b) / (jUptimeMillis - j3);
        }
        this.f7893e = jUptimeMillis;
        this.f7889a = i3;
        this.f7890b = i4;
        return z3;
    }
}
