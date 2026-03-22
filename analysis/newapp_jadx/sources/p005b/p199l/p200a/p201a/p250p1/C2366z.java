package p005b.p199l.p200a.p201a.p250p1;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import androidx.annotation.Nullable;

/* renamed from: b.l.a.a.p1.z */
/* loaded from: classes.dex */
public final class C2366z implements InterfaceC2346f {
    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f
    /* renamed from: a */
    public long mo2352a() {
        return SystemClock.uptimeMillis();
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f
    /* renamed from: b */
    public C2338a0 mo2353b(Looper looper, @Nullable Handler.Callback callback) {
        return new C2338a0(new Handler(looper, callback));
    }

    @Override // p005b.p199l.p200a.p201a.p250p1.InterfaceC2346f
    /* renamed from: c */
    public long mo2354c() {
        return SystemClock.elapsedRealtime();
    }
}
