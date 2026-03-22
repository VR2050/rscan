package p005b.p199l.p200a.p201a.p202a1;

import android.annotation.TargetApi;
import android.media.AudioAttributes;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.a1.i */
/* loaded from: classes.dex */
public final class C1917i {

    /* renamed from: a */
    public static final C1917i f3066a = new C1917i(0, 0, 1, 1, null);

    /* renamed from: b */
    public final int f3067b;

    /* renamed from: c */
    public final int f3068c;

    /* renamed from: d */
    public final int f3069d;

    /* renamed from: e */
    public final int f3070e;

    /* renamed from: f */
    @Nullable
    public AudioAttributes f3071f;

    public C1917i(int i2, int i3, int i4, int i5, a aVar) {
        this.f3067b = i2;
        this.f3068c = i3;
        this.f3069d = i4;
        this.f3070e = i5;
    }

    @TargetApi(21)
    /* renamed from: a */
    public AudioAttributes m1266a() {
        if (this.f3071f == null) {
            AudioAttributes.Builder usage = new AudioAttributes.Builder().setContentType(this.f3067b).setFlags(this.f3068c).setUsage(this.f3069d);
            if (C2344d0.f6035a >= 29) {
                usage.setAllowedCapturePolicy(this.f3070e);
            }
            this.f3071f = usage.build();
        }
        return this.f3071f;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C1917i.class != obj.getClass()) {
            return false;
        }
        C1917i c1917i = (C1917i) obj;
        return this.f3067b == c1917i.f3067b && this.f3068c == c1917i.f3068c && this.f3069d == c1917i.f3069d && this.f3070e == c1917i.f3070e;
    }

    public int hashCode() {
        return ((((((527 + this.f3067b) * 31) + this.f3068c) * 31) + this.f3069d) * 31) + this.f3070e;
    }
}
