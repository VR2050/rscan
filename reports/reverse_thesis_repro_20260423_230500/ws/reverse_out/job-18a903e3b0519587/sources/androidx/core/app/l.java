package androidx.core.app;

import android.content.res.Configuration;

/* JADX INFO: loaded from: classes.dex */
public final class l {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final boolean f4254a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private Configuration f4255b;

    public l(boolean z3) {
        this.f4254a = z3;
    }

    public final boolean a() {
        return this.f4254a;
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public l(boolean z3, Configuration configuration) {
        this(z3);
        t2.j.f(configuration, "newConfig");
        this.f4255b = configuration;
    }
}
