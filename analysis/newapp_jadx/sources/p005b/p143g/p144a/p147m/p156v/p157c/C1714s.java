package p005b.p143g.p144a.p147m.p156v.p157c;

import android.os.Build;
import android.util.Log;
import androidx.annotation.GuardedBy;
import androidx.annotation.VisibleForTesting;
import java.io.File;

/* renamed from: b.g.a.m.v.c.s */
/* loaded from: classes.dex */
public final class C1714s {

    /* renamed from: a */
    public static final File f2523a = new File("/proc/self/fd");

    /* renamed from: b */
    public static volatile C1714s f2524b;

    /* renamed from: c */
    public final boolean f2525c;

    /* renamed from: d */
    public final int f2526d;

    /* renamed from: e */
    public final int f2527e;

    /* renamed from: f */
    @GuardedBy("this")
    public int f2528f;

    /* renamed from: g */
    @GuardedBy("this")
    public boolean f2529g = true;

    @VisibleForTesting
    public C1714s() {
        boolean z = true;
        String str = Build.MODEL;
        if (str != null && str.length() >= 7) {
            String substring = str.substring(0, 7);
            substring.hashCode();
            switch (substring) {
                case "SM-A520":
                case "SM-G930":
                case "SM-G935":
                case "SM-G960":
                case "SM-G965":
                case "SM-J720":
                case "SM-N935":
                    if (Build.VERSION.SDK_INT == 26) {
                        z = false;
                        break;
                    }
                    break;
            }
        }
        this.f2525c = z;
        if (Build.VERSION.SDK_INT >= 28) {
            this.f2526d = 20000;
            this.f2527e = 0;
        } else {
            this.f2526d = 700;
            this.f2527e = 128;
        }
    }

    /* renamed from: a */
    public static C1714s m1017a() {
        if (f2524b == null) {
            synchronized (C1714s.class) {
                if (f2524b == null) {
                    f2524b = new C1714s();
                }
            }
        }
        return f2524b;
    }

    /* renamed from: b */
    public boolean m1018b(int i2, int i3, boolean z, boolean z2) {
        int i4;
        boolean z3;
        if (!z || !this.f2525c || Build.VERSION.SDK_INT < 26 || z2 || i2 < (i4 = this.f2527e) || i3 < i4) {
            return false;
        }
        synchronized (this) {
            int i5 = this.f2528f + 1;
            this.f2528f = i5;
            if (i5 >= 50) {
                this.f2528f = 0;
                boolean z4 = f2523a.list().length < this.f2526d;
                this.f2529g = z4;
                if (!z4) {
                    Log.isLoggable("Downsampler", 5);
                }
            }
            z3 = this.f2529g;
        }
        return z3;
    }
}
