package X;

/* JADX INFO: loaded from: classes.dex */
public abstract class o {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final n f2852a = new b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final n f2853b = new c();

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final n f2854c = new d();

    class a implements n {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        final /* synthetic */ Object f2855a;

        a(Object obj) {
            this.f2855a = obj;
        }

        @Override // X.n
        public Object get() {
            return this.f2855a;
        }
    }

    class b implements n {
        b() {
        }

        @Override // X.n
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Boolean get() {
            return Boolean.TRUE;
        }
    }

    class c implements n {
        c() {
        }

        @Override // X.n
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public Boolean get() {
            return Boolean.FALSE;
        }
    }

    class d implements n {
        d() {
        }

        @Override // X.n
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public String get() {
            return "";
        }
    }

    public static n a(Object obj) {
        return new a(obj);
    }
}
