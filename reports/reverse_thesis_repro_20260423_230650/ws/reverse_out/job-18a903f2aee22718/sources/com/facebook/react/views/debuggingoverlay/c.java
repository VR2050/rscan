package com.facebook.react.views.debuggingoverlay;

import android.graphics.RectF;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f7781a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final RectF f7782b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f7783c;

    public c(int i3, RectF rectF, int i4) {
        j.f(rectF, "rectangle");
        this.f7781a = i3;
        this.f7782b = rectF;
        this.f7783c = i4;
    }

    public final int a() {
        return this.f7783c;
    }

    public final int b() {
        return this.f7781a;
    }

    public final RectF c() {
        return this.f7782b;
    }
}
