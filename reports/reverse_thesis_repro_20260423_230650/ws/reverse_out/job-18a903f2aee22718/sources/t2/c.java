package t2;

import java.io.Serializable;
import r2.C0678b;

/* JADX INFO: loaded from: classes.dex */
public abstract class c implements x2.a, Serializable {

    /* JADX INFO: renamed from: h, reason: collision with root package name */
    public static final Object f10191h = a.f10198b;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private transient x2.a f10192b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    protected final Object f10193c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final Class f10194d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    private final String f10195e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    private final String f10196f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private final boolean f10197g;

    private static class a implements Serializable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private static final a f10198b = new a();

        private a() {
        }
    }

    protected c(Object obj, Class cls, String str, String str2, boolean z3) {
        this.f10193c = obj;
        this.f10194d = cls;
        this.f10195e = str;
        this.f10196f = str2;
        this.f10197g = z3;
    }

    public x2.a b() {
        x2.a aVar = this.f10192b;
        if (aVar != null) {
            return aVar;
        }
        x2.a aVarE = e();
        this.f10192b = aVarE;
        return aVarE;
    }

    protected abstract x2.a e();

    public Object f() {
        return this.f10193c;
    }

    public String g() {
        return this.f10195e;
    }

    public x2.c h() {
        Class cls = this.f10194d;
        if (cls == null) {
            return null;
        }
        return this.f10197g ? u.c(cls) : u.b(cls);
    }

    protected x2.a i() {
        x2.a aVarB = b();
        if (aVarB != this) {
            return aVarB;
        }
        throw new C0678b();
    }

    public String j() {
        return this.f10196f;
    }
}
