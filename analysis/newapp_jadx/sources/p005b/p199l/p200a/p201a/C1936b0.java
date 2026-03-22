package p005b.p199l.p200a.p201a;

import android.os.SystemClock;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;

/* renamed from: b.l.a.a.b0 */
/* loaded from: classes.dex */
public final class C1936b0 extends Exception {

    /* renamed from: c */
    public final int f3245c;

    /* renamed from: e */
    public final int f3246e;

    /* renamed from: f */
    @Nullable
    public final Format f3247f;

    /* renamed from: g */
    public final int f3248g;

    public C1936b0(int i2, Throwable th) {
        super(th);
        this.f3245c = i2;
        this.f3246e = -1;
        this.f3247f = null;
        this.f3248g = 4;
        SystemClock.elapsedRealtime();
    }

    public C1936b0(int i2, Throwable th, int i3, @Nullable Format format, int i4) {
        super(th);
        this.f3245c = i2;
        this.f3246e = i3;
        this.f3247f = format;
        this.f3248g = i4;
        SystemClock.elapsedRealtime();
    }
}
