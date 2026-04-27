package com.facebook.react.devsupport;

import android.os.Build;

/* JADX INFO: loaded from: classes.dex */
public final class n0 {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final n0 f6899a = new n0();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final int f6900b;

    static {
        f6900b = Build.VERSION.SDK_INT < 26 ? 2006 : 2038;
    }

    private n0() {
    }
}
