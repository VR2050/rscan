package R;

import X.k;
import android.net.Uri;

/* JADX INFO: loaded from: classes.dex */
public class i implements d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final String f2619a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    final boolean f2620b;

    public i(String str) {
        this(str, false);
    }

    @Override // R.d
    public boolean a() {
        return this.f2620b;
    }

    @Override // R.d
    public boolean b(Uri uri) {
        return this.f2619a.contains(uri.toString());
    }

    @Override // R.d
    public String c() {
        return this.f2619a;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof i) {
            return this.f2619a.equals(((i) obj).f2619a);
        }
        return false;
    }

    public int hashCode() {
        return this.f2619a.hashCode();
    }

    public String toString() {
        return this.f2619a;
    }

    public i(String str, boolean z3) {
        this.f2619a = (String) k.g(str);
        this.f2620b = z3;
    }
}
