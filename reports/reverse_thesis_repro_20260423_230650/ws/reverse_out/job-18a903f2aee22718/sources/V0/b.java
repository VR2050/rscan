package V0;

import java.util.Arrays;
import t2.j;
import t2.w;

/* JADX INFO: loaded from: classes.dex */
public final class b {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2811a;

    public b(int i3) {
        this.f2811a = i3;
    }

    public final int a() {
        return this.f2811a;
    }

    public String toString() {
        w wVar = w.f10219a;
        String str = String.format(null, "Status: %d", Arrays.copyOf(new Object[]{Integer.valueOf(this.f2811a)}, 1));
        j.e(str, "format(...)");
        return str;
    }
}
