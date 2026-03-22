package p005b.p143g.p144a.p147m.p150t.p152d0;

import android.app.ActivityManager;
import android.content.Context;
import android.os.Build;
import android.text.format.Formatter;
import android.util.DisplayMetrics;
import android.util.Log;
import androidx.appcompat.widget.ActivityChooserModel;

/* renamed from: b.g.a.m.t.d0.j */
/* loaded from: classes.dex */
public final class C1634j {

    /* renamed from: a */
    public final int f2120a;

    /* renamed from: b */
    public final int f2121b;

    /* renamed from: c */
    public final Context f2122c;

    /* renamed from: d */
    public final int f2123d;

    /* renamed from: b.g.a.m.t.d0.j$a */
    public static final class a {

        /* renamed from: a */
        public static final int f2124a;

        /* renamed from: b */
        public final Context f2125b;

        /* renamed from: c */
        public ActivityManager f2126c;

        /* renamed from: d */
        public c f2127d;

        /* renamed from: e */
        public float f2128e = 2.0f;

        /* renamed from: f */
        public float f2129f;

        static {
            f2124a = Build.VERSION.SDK_INT < 26 ? 4 : 1;
        }

        public a(Context context) {
            this.f2129f = f2124a;
            this.f2125b = context;
            this.f2126c = (ActivityManager) context.getSystemService(ActivityChooserModel.ATTRIBUTE_ACTIVITY);
            this.f2127d = new b(context.getResources().getDisplayMetrics());
            if (Build.VERSION.SDK_INT < 26 || !this.f2126c.isLowRamDevice()) {
                return;
            }
            this.f2129f = 0.0f;
        }
    }

    /* renamed from: b.g.a.m.t.d0.j$b */
    public static final class b implements c {

        /* renamed from: a */
        public final DisplayMetrics f2130a;

        public b(DisplayMetrics displayMetrics) {
            this.f2130a = displayMetrics;
        }
    }

    /* renamed from: b.g.a.m.t.d0.j$c */
    public interface c {
    }

    public C1634j(a aVar) {
        this.f2122c = aVar.f2125b;
        int i2 = aVar.f2126c.isLowRamDevice() ? 2097152 : 4194304;
        this.f2123d = i2;
        int round = Math.round(r1.getMemoryClass() * 1024 * 1024 * (aVar.f2126c.isLowRamDevice() ? 0.33f : 0.4f));
        DisplayMetrics displayMetrics = ((b) aVar.f2127d).f2130a;
        float f2 = displayMetrics.widthPixels * displayMetrics.heightPixels * 4;
        int round2 = Math.round(aVar.f2129f * f2);
        int round3 = Math.round(f2 * aVar.f2128e);
        int i3 = round - i2;
        if (round3 + round2 <= i3) {
            this.f2121b = round3;
            this.f2120a = round2;
        } else {
            float f3 = i3;
            float f4 = aVar.f2129f;
            float f5 = aVar.f2128e;
            float f6 = f3 / (f4 + f5);
            this.f2121b = Math.round(f5 * f6);
            this.f2120a = Math.round(f6 * aVar.f2129f);
        }
        if (Log.isLoggable("MemorySizeCalculator", 3)) {
            m901a(this.f2121b);
            m901a(this.f2120a);
            m901a(i2);
            m901a(round);
            aVar.f2126c.getMemoryClass();
            aVar.f2126c.isLowRamDevice();
        }
    }

    /* renamed from: a */
    public final String m901a(int i2) {
        return Formatter.formatFileSize(this.f2122c, i2);
    }
}
