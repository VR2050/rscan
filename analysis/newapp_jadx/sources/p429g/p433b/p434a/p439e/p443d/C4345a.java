package p429g.p433b.p434a.p439e.p443d;

import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: g.b.a.e.d.a */
/* loaded from: classes2.dex */
public final class C4345a {

    /* renamed from: a */
    public static final /* synthetic */ int f11199a = 0;

    /* renamed from: g.b.a.e.d.a$a */
    public static final class a extends Throwable {
        private static final long serialVersionUID = -4649703670690200604L;

        public a() {
            super("No further exceptions");
        }

        @Override // java.lang.Throwable
        public Throwable fillInStackTrace() {
            return this;
        }
    }

    static {
        new a();
    }

    /* renamed from: a */
    public static <T> T m4914a(T t, String str) {
        if (t != null) {
            return t;
        }
        throw new NullPointerException(C1499a.m637w(str, " Null values are generally not allowed in 3.x operators and sources."));
    }
}
