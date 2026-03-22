package p005b.p199l.p200a.p201a.p250p1;

import android.os.Handler;
import android.os.Message;
import androidx.annotation.Nullable;

/* renamed from: b.l.a.a.p1.a0 */
/* loaded from: classes.dex */
public final class C2338a0 {

    /* renamed from: a */
    public final Handler f6024a;

    public C2338a0(Handler handler) {
        this.f6024a = handler;
    }

    /* renamed from: a */
    public Message m2297a(int i2, int i3, int i4) {
        return this.f6024a.obtainMessage(i2, i3, i4);
    }

    /* renamed from: b */
    public Message m2298b(int i2, @Nullable Object obj) {
        return this.f6024a.obtainMessage(i2, obj);
    }

    /* renamed from: c */
    public boolean m2299c(int i2) {
        return this.f6024a.sendEmptyMessage(i2);
    }
}
