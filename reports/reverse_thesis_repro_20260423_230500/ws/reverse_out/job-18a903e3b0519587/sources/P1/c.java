package P1;

import android.view.View;
import android.view.animation.Animation;
import android.view.animation.ScaleAnimation;
import com.facebook.react.uimanager.P;

/* JADX INFO: loaded from: classes.dex */
abstract class c extends P1.a {

    static /* synthetic */ class a {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        static final /* synthetic */ int[] f2167a;

        static {
            int[] iArr = new int[b.values().length];
            f2167a = iArr;
            try {
                iArr[b.f2161c.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                f2167a[b.f2164f.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                f2167a[b.f2162d.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                f2167a[b.f2163e.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
        }
    }

    c() {
    }

    @Override // P1.a
    Animation b(View view, int i3, int i4, int i5, int i6) {
        b bVar = this.f2158c;
        if (bVar == null) {
            throw new P("Missing animated property from animation config");
        }
        int i7 = a.f2167a[bVar.ordinal()];
        if (i7 == 1) {
            return new l(view, g() ? view.getAlpha() : 0.0f, g() ? 0.0f : view.getAlpha());
        }
        if (i7 == 2) {
            float f3 = g() ? 1.0f : 0.0f;
            float f4 = g() ? 0.0f : 1.0f;
            return new ScaleAnimation(f3, f4, f3, f4, 1, 0.5f, 1, 0.5f);
        }
        if (i7 == 3) {
            return new ScaleAnimation(g() ? 1.0f : 0.0f, g() ? 0.0f : 1.0f, 1.0f, 1.0f, 1, 0.5f, 1, 0.0f);
        }
        if (i7 == 4) {
            return new ScaleAnimation(1.0f, 1.0f, g() ? 1.0f : 0.0f, g() ? 0.0f : 1.0f, 1, 0.0f, 1, 0.5f);
        }
        throw new P("Missing animation for property : " + this.f2158c);
    }

    @Override // P1.a
    boolean e() {
        return this.f2159d > 0 && this.f2158c != null;
    }

    abstract boolean g();
}
