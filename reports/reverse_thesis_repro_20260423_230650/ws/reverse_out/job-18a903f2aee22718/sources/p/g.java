package p;

import android.content.Context;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.CancellationSignal;
import android.os.Handler;

/* JADX INFO: loaded from: classes.dex */
public abstract class g {

    public static class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f9767a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final b[] f9768b;

        public a(int i3, b[] bVarArr) {
            this.f9767a = i3;
            this.f9768b = bVarArr;
        }

        static a a(int i3, b[] bVarArr) {
            return new a(i3, bVarArr);
        }

        public b[] b() {
            return this.f9768b;
        }

        public int c() {
            return this.f9767a;
        }
    }

    public static class b {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final Uri f9769a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f9770b;

        /* JADX INFO: renamed from: c, reason: collision with root package name */
        private final int f9771c;

        /* JADX INFO: renamed from: d, reason: collision with root package name */
        private final boolean f9772d;

        /* JADX INFO: renamed from: e, reason: collision with root package name */
        private final int f9773e;

        public b(Uri uri, int i3, int i4, boolean z3, int i5) {
            this.f9769a = (Uri) q.g.f(uri);
            this.f9770b = i3;
            this.f9771c = i4;
            this.f9772d = z3;
            this.f9773e = i5;
        }

        static b a(Uri uri, int i3, int i4, boolean z3, int i5) {
            return new b(uri, i3, i4, z3, i5);
        }

        public int b() {
            return this.f9773e;
        }

        public int c() {
            return this.f9770b;
        }

        public Uri d() {
            return this.f9769a;
        }

        public int e() {
            return this.f9771c;
        }

        public boolean f() {
            return this.f9772d;
        }
    }

    public static class c {
        public abstract void a(int i3);

        public abstract void b(Typeface typeface);
    }

    public static Typeface a(Context context, CancellationSignal cancellationSignal, b[] bVarArr) {
        return androidx.core.graphics.d.b(context, cancellationSignal, bVarArr, 0);
    }

    public static a b(Context context, CancellationSignal cancellationSignal, e eVar) {
        return d.e(context, eVar, cancellationSignal);
    }

    public static Typeface c(Context context, e eVar, int i3, boolean z3, int i4, Handler handler, c cVar) {
        C0641a c0641a = new C0641a(cVar, handler);
        return z3 ? f.e(context, eVar, c0641a, i3, i4) : f.d(context, eVar, i3, null, c0641a);
    }
}
