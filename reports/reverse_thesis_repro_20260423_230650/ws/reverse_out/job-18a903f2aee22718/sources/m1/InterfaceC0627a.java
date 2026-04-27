package m1;

import android.view.View;
import com.facebook.react.uimanager.C0444f0;
import com.facebook.yoga.p;

/* JADX INFO: renamed from: m1.a, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public interface InterfaceC0627a {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0139a f9607a = C0139a.f9608a;

    /* JADX INFO: renamed from: m1.a$a, reason: collision with other inner class name */
    public static final class C0139a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ C0139a f9608a = new C0139a();

        private C0139a() {
        }

        public final float a(int i3) {
            int mode = View.MeasureSpec.getMode(i3);
            int size = View.MeasureSpec.getSize(i3);
            if (mode == 0) {
                return Float.POSITIVE_INFINITY;
            }
            return size;
        }

        public final float b(int i3) {
            int mode = View.MeasureSpec.getMode(i3);
            int size = View.MeasureSpec.getSize(i3);
            if (mode == 1073741824) {
                return size;
            }
            return 0.0f;
        }

        public final p c(float f3, float f4) {
            return f3 == f4 ? p.EXACTLY : Float.isInfinite(f4) ? p.UNDEFINED : p.AT_MOST;
        }

        public final float d(float f3, float f4) {
            if (f3 == f4) {
                return C0444f0.f7603a.b(f4);
            }
            if (Float.isInfinite(f4)) {
                return Float.POSITIVE_INFINITY;
            }
            return C0444f0.f7603a.b(f4);
        }
    }

    static float a(int i3) {
        return f9607a.b(i3);
    }

    static p b(float f3, float f4) {
        return f9607a.c(f3, f4);
    }

    static float c(float f3, float f4) {
        return f9607a.d(f3, f4);
    }

    static float d(int i3) {
        return f9607a.a(i3);
    }
}
