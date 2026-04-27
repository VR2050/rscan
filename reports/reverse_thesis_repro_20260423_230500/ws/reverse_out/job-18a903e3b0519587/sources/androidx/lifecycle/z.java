package androidx.lifecycle;

import E.a;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class z {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final B f5186a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final b f5187b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final E.a f5188c;

    public static class a extends c {

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        public static final C0076a f5189d = new C0076a(null);

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        public static final a.b f5190e = C0076a.C0077a.f5191a;

        /* JADX INFO: renamed from: androidx.lifecycle.z$a$a, reason: collision with other inner class name */
        public static final class C0076a {

            /* JADX INFO: renamed from: androidx.lifecycle.z$a$a$a, reason: collision with other inner class name */
            private static final class C0077a implements a.b {

                /* JADX INFO: renamed from: a, reason: collision with root package name */
                public static final C0077a f5191a = new C0077a();

                private C0077a() {
                }
            }

            public /* synthetic */ C0076a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            private C0076a() {
            }
        }
    }

    public interface b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final a f5192a = a.f5193a;

        public static final class a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            static final /* synthetic */ a f5193a = new a();

            private a() {
            }
        }

        default y a(Class cls) {
            t2.j.f(cls, "modelClass");
            throw new UnsupportedOperationException("Factory.create(String) is unsupported.  This Factory requires `CreationExtras` to be passed into `create` method.");
        }

        default y b(Class cls, E.a aVar) {
            t2.j.f(cls, "modelClass");
            t2.j.f(aVar, "extras");
            return a(cls);
        }
    }

    public static class c implements b {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public static final a f5194b = new a(null);

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        public static final a.b f5195c = a.C0078a.f5196a;

        public static final class a {

            /* JADX INFO: renamed from: androidx.lifecycle.z$c$a$a, reason: collision with other inner class name */
            private static final class C0078a implements a.b {

                /* JADX INFO: renamed from: a, reason: collision with root package name */
                public static final C0078a f5196a = new C0078a();

                private C0078a() {
                }
            }

            public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
                this();
            }

            private a() {
            }
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public z(B b3, b bVar) {
        this(b3, bVar, null, 4, null);
        t2.j.f(b3, "store");
        t2.j.f(bVar, "factory");
    }

    public y a(Class cls) {
        t2.j.f(cls, "modelClass");
        String canonicalName = cls.getCanonicalName();
        if (canonicalName == null) {
            throw new IllegalArgumentException("Local and anonymous classes can not be ViewModels");
        }
        return b("androidx.lifecycle.ViewModelProvider.DefaultKey:" + canonicalName, cls);
    }

    public y b(String str, Class cls) {
        y yVarA;
        t2.j.f(str, "key");
        t2.j.f(cls, "modelClass");
        y yVarB = this.f5186a.b(str);
        if (cls.isInstance(yVarB)) {
            t2.j.d(yVarB, "null cannot be cast to non-null type T of androidx.lifecycle.ViewModelProvider.get");
            return yVarB;
        }
        E.d dVar = new E.d(this.f5188c);
        dVar.b(c.f5195c, str);
        try {
            yVarA = this.f5187b.b(cls, dVar);
        } catch (AbstractMethodError unused) {
            yVarA = this.f5187b.a(cls);
        }
        this.f5186a.d(str, yVarA);
        return yVarA;
    }

    public z(B b3, b bVar, E.a aVar) {
        t2.j.f(b3, "store");
        t2.j.f(bVar, "factory");
        t2.j.f(aVar, "defaultCreationExtras");
        this.f5186a = b3;
        this.f5187b = bVar;
        this.f5188c = aVar;
    }

    public /* synthetic */ z(B b3, b bVar, E.a aVar, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this(b3, bVar, (i3 & 4) != 0 ? a.C0012a.f610b : aVar);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public z(C c3, b bVar) {
        this(c3.r(), bVar, A.a(c3));
        t2.j.f(c3, "owner");
        t2.j.f(bVar, "factory");
    }
}
