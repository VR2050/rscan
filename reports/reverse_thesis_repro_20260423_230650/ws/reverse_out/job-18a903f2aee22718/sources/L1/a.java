package L1;

import android.view.View;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final a f1713a = new a();

    private a() {
    }

    public static final int a(int i3) {
        return i3 % 2 == 0 ? 2 : 1;
    }

    public static final int b(int i3, int i4) {
        int i5 = i4 == -1 ? 1 : 2;
        if (i5 == 1 && !d(i3) && i3 % 2 == 0) {
            return 2;
        }
        return i5;
    }

    public static final int c(View view) {
        j.f(view, "view");
        return a(view.getId());
    }

    public static final boolean d(int i3) {
        return i3 % 10 == 1;
    }
}
