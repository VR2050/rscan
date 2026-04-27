package com.facebook.react.modules.network;

import B2.C0165c;
import B2.z;
import android.content.Context;
import java.io.File;
import java.util.concurrent.TimeUnit;

/* JADX INFO: loaded from: classes.dex */
public final class g {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final g f7137a = new g();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static z f7138b;

    private g() {
    }

    public static final z a() {
        return c().c();
    }

    public static final z b(Context context) {
        t2.j.f(context, "context");
        return d(context).c();
    }

    public static final z.a c() {
        z.a aVar = new z.a();
        TimeUnit timeUnit = TimeUnit.MILLISECONDS;
        return aVar.f(0L, timeUnit).S(0L, timeUnit).W(0L, timeUnit).h(new m());
    }

    public static final z.a d(Context context) {
        t2.j.f(context, "context");
        return e(context, 10485760);
    }

    public static final z.a e(Context context, int i3) {
        t2.j.f(context, "context");
        z.a aVarC = c();
        return i3 == 0 ? aVarC : aVarC.d(new C0165c(new File(context.getCacheDir(), "http-cache"), i3));
    }

    public static final z f() {
        z zVar = f7138b;
        if (zVar != null) {
            return zVar;
        }
        z zVarA = a();
        f7138b = zVarA;
        return zVarA;
    }
}
