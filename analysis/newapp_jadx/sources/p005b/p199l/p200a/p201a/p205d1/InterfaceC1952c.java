package p005b.p199l.p200a.p201a.p205d1;

import androidx.annotation.Nullable;
import java.io.IOException;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1956g;

/* renamed from: b.l.a.a.d1.c */
/* loaded from: classes.dex */
public interface InterfaceC1952c<T extends InterfaceC1956g> {

    /* renamed from: b.l.a.a.d1.c$a */
    public static class a extends IOException {
        public a(Throwable th) {
            super(th);
        }
    }

    /* renamed from: a */
    boolean mo1448a();

    void acquire();

    @Nullable
    /* renamed from: b */
    T mo1449b();

    @Nullable
    /* renamed from: c */
    a mo1450c();

    int getState();

    void release();
}
