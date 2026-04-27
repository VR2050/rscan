package w2;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class c extends w2.a {

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public static final a f10305f = new a(null);

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    private static final c f10306g = new c(1, 0);

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final c a() {
            return c.f10306g;
        }

        private a() {
        }
    }

    public c(int i3, int i4) {
        super(i3, i4, 1);
    }

    @Override // w2.a
    public boolean equals(Object obj) {
        if (obj instanceof c) {
            if (!isEmpty() || !((c) obj).isEmpty()) {
                c cVar = (c) obj;
                if (a() != cVar.a() || b() != cVar.b()) {
                }
            }
            return true;
        }
        return false;
    }

    public Integer h() {
        return Integer.valueOf(b());
    }

    @Override // w2.a
    public int hashCode() {
        if (isEmpty()) {
            return -1;
        }
        return (a() * 31) + b();
    }

    public Integer i() {
        return Integer.valueOf(a());
    }

    @Override // w2.a
    public boolean isEmpty() {
        return a() > b();
    }

    @Override // w2.a
    public String toString() {
        return a() + ".." + b();
    }
}
