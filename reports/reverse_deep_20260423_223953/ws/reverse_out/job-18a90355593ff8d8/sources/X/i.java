package X;

import java.util.Arrays;

/* JADX INFO: loaded from: classes.dex */
public abstract class i {

    public static final class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final String f2845a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final C0046a f2846b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private C0046a f2847c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private boolean f2848d;

        /* JADX INFO: renamed from: X.i$a$a, reason: collision with other inner class name */
        private static final class C0046a {

            /* JADX INFO: renamed from: a, reason: collision with root package name */
            String f2849a;

            /* JADX INFO: renamed from: b, reason: collision with root package name */
            Object f2850b;

            /* JADX INFO: renamed from: c, reason: collision with root package name */
            C0046a f2851c;

            private C0046a() {
            }
        }

        private C0046a d() {
            C0046a c0046a = new C0046a();
            this.f2847c.f2851c = c0046a;
            this.f2847c = c0046a;
            return c0046a;
        }

        private a e(String str, Object obj) {
            C0046a c0046aD = d();
            c0046aD.f2850b = obj;
            c0046aD.f2849a = (String) k.g(str);
            return this;
        }

        public a a(String str, int i3) {
            return e(str, String.valueOf(i3));
        }

        public a b(String str, Object obj) {
            return e(str, obj);
        }

        public a c(String str, boolean z3) {
            return e(str, String.valueOf(z3));
        }

        public String toString() {
            boolean z3 = this.f2848d;
            StringBuilder sb = new StringBuilder(32);
            sb.append(this.f2845a);
            sb.append('{');
            String str = "";
            for (C0046a c0046a = this.f2846b.f2851c; c0046a != null; c0046a = c0046a.f2851c) {
                Object obj = c0046a.f2850b;
                if (!z3 || obj != null) {
                    sb.append(str);
                    String str2 = c0046a.f2849a;
                    if (str2 != null) {
                        sb.append(str2);
                        sb.append('=');
                    }
                    if (obj == null || !obj.getClass().isArray()) {
                        sb.append(obj);
                    } else {
                        String strDeepToString = Arrays.deepToString(new Object[]{obj});
                        sb.append((CharSequence) strDeepToString, 1, strDeepToString.length() - 1);
                    }
                    str = ", ";
                }
            }
            sb.append('}');
            return sb.toString();
        }

        private a(String str) {
            C0046a c0046a = new C0046a();
            this.f2846b = c0046a;
            this.f2847c = c0046a;
            this.f2848d = false;
            this.f2845a = (String) k.g(str);
        }
    }

    public static boolean a(Object obj, Object obj2) {
        return obj == obj2 || (obj != null && obj.equals(obj2));
    }

    public static a b(Object obj) {
        return new a(obj.getClass().getSimpleName());
    }
}
