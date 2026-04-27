package R;

import X.k;
import android.net.Uri;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public class f implements d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    final List f2616a;

    public f(List list) {
        this.f2616a = (List) k.g(list);
    }

    @Override // R.d
    public boolean a() {
        return false;
    }

    @Override // R.d
    public boolean b(Uri uri) {
        for (int i3 = 0; i3 < this.f2616a.size(); i3++) {
            if (((d) this.f2616a.get(i3)).b(uri)) {
                return true;
            }
        }
        return false;
    }

    @Override // R.d
    public String c() {
        return ((d) this.f2616a.get(0)).c();
    }

    public List d() {
        return this.f2616a;
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof f) {
            return this.f2616a.equals(((f) obj).f2616a);
        }
        return false;
    }

    public int hashCode() {
        return this.f2616a.hashCode();
    }

    public String toString() {
        return "MultiCacheKey:" + this.f2616a.toString();
    }
}
