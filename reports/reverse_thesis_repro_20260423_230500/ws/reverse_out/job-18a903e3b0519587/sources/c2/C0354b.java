package c2;

import java.util.ArrayList;
import java.util.List;
import t2.j;

/* JADX INFO: renamed from: c2.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0354b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0354b f5688a = new C0354b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static boolean f5689b;

    /* JADX INFO: renamed from: c2.b$a */
    public static abstract class a {
        public abstract a a(String str, int i3);

        public abstract a b(String str, Object obj);

        public abstract void c();
    }

    /* JADX INFO: renamed from: c2.b$b, reason: collision with other inner class name */
    private static final class C0089b extends a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final long f5690a;

        public C0089b(long j3) {
            this.f5690a = j3;
        }

        @Override // c2.C0354b.a
        public a a(String str, int i3) {
            j.f(str, "key");
            return this;
        }

        @Override // c2.C0354b.a
        public a b(String str, Object obj) {
            j.f(str, "key");
            j.f(obj, "value");
            return this;
        }

        @Override // c2.C0354b.a
        public void c() {
            C0353a.i(this.f5690a);
        }
    }

    /* JADX INFO: renamed from: c2.b$c */
    private static final class c extends a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final long f5691a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final String f5692b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final List f5693c;

        public c(long j3, String str) {
            j.f(str, "sectionName");
            this.f5691a = j3;
            this.f5692b = str;
            this.f5693c = new ArrayList();
        }

        private final void d(String str, String str2) {
            this.f5693c.add(str + ": " + str2);
        }

        @Override // c2.C0354b.a
        public a a(String str, int i3) {
            j.f(str, "key");
            d(str, String.valueOf(i3));
            return this;
        }

        @Override // c2.C0354b.a
        public a b(String str, Object obj) {
            j.f(str, "key");
            j.f(obj, "value");
            d(str, obj.toString());
            return this;
        }

        @Override // c2.C0354b.a
        public void c() {
            String str;
            long j3 = this.f5691a;
            String str2 = this.f5692b;
            if (!C0354b.f5689b || this.f5693c.isEmpty()) {
                str = "";
            } else {
                str = " (" + AbstractC0355c.a(", ", this.f5693c) + ")";
            }
            C0353a.c(j3, str2 + str);
        }
    }

    private C0354b() {
    }

    public static final a a(long j3, String str) {
        j.f(str, "sectionName");
        return new c(j3, str);
    }

    public static final a b(long j3) {
        return new C0089b(j3);
    }
}
