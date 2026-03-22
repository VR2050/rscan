package p005b.p199l.p200a.p201a.p205d1;

import android.os.Looper;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.drm.DrmInitData;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1952c;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1956g;

/* renamed from: b.l.a.a.d1.e */
/* loaded from: classes.dex */
public interface InterfaceC1954e<T extends InterfaceC1956g> {

    /* renamed from: a */
    public static final InterfaceC1954e<InterfaceC1956g> f3383a = new a();

    /* renamed from: b.l.a.a.d1.e$a */
    public static class a implements InterfaceC1954e<InterfaceC1956g> {
        @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
        @Nullable
        /* renamed from: a */
        public Class<InterfaceC1956g> mo1442a(DrmInitData drmInitData) {
            return null;
        }

        @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
        /* renamed from: b */
        public /* synthetic */ void mo1443b() {
            C1953d.m1452b(this);
        }

        @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
        /* renamed from: c */
        public /* synthetic */ InterfaceC1952c<InterfaceC1956g> mo1444c(Looper looper, int i2) {
            return C1953d.m1451a(this, looper, i2);
        }

        @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
        /* renamed from: d */
        public InterfaceC1952c<InterfaceC1956g> mo1445d(Looper looper, DrmInitData drmInitData) {
            return new C1955f(new InterfaceC1952c.a(new C1958i(1)));
        }

        @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
        /* renamed from: e */
        public boolean mo1446e(DrmInitData drmInitData) {
            return false;
        }

        @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
        public /* synthetic */ void release() {
            C1953d.m1453c(this);
        }
    }

    @Nullable
    /* renamed from: a */
    Class<? extends InterfaceC1956g> mo1442a(DrmInitData drmInitData);

    /* renamed from: b */
    void mo1443b();

    @Nullable
    /* renamed from: c */
    InterfaceC1952c<T> mo1444c(Looper looper, int i2);

    /* renamed from: d */
    InterfaceC1952c<T> mo1445d(Looper looper, DrmInitData drmInitData);

    /* renamed from: e */
    boolean mo1446e(DrmInitData drmInitData);

    void release();
}
