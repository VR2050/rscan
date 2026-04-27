package w0;

import android.view.View;
import android.view.ViewGroup;

/* JADX INFO: renamed from: w0.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0712a {

    /* JADX INFO: renamed from: w0.a$a, reason: collision with other inner class name */
    public static class C0154a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public int f10281a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public int f10282b;
    }

    private static boolean a(int i3) {
        return i3 == 0 || i3 == -2;
    }

    public static void b(C0154a c0154a, float f3, ViewGroup.LayoutParams layoutParams, int i3, int i4) {
        if (f3 <= 0.0f || layoutParams == null) {
            return;
        }
        if (a(layoutParams.height)) {
            c0154a.f10282b = View.MeasureSpec.makeMeasureSpec(View.resolveSize((int) (((View.MeasureSpec.getSize(c0154a.f10281a) - i3) / f3) + i4), c0154a.f10282b), 1073741824);
        } else if (a(layoutParams.width)) {
            c0154a.f10281a = View.MeasureSpec.makeMeasureSpec(View.resolveSize((int) (((View.MeasureSpec.getSize(c0154a.f10282b) - i4) * f3) + i3), c0154a.f10281a), 1073741824);
        }
    }
}
