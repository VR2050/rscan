package p005b.p199l.p200a.p201a.p205d1;

import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.drm.DrmInitData;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1956g;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@TargetApi(18)
/* renamed from: b.l.a.a.d1.b */
/* loaded from: classes.dex */
public class C1951b<T extends InterfaceC1956g> implements InterfaceC1954e<T> {

    /* renamed from: b */
    public int f3378b;

    /* renamed from: c */
    @Nullable
    public C1950a<T> f3379c;

    /* renamed from: d */
    @Nullable
    public Looper f3380d;

    /* renamed from: e */
    @Nullable
    public volatile C1951b<T>.b f3381e;

    @SuppressLint({"HandlerLeak"})
    /* renamed from: b.l.a.a.d1.b$b */
    public class b extends Handler {
        public b(Looper looper) {
            super(looper);
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            if (((byte[]) message.obj) == null) {
                return;
            }
            Objects.requireNonNull(C1951b.this);
            throw null;
        }
    }

    /* renamed from: b.l.a.a.d1.b$c */
    public static final class c extends Exception {
        public c(UUID uuid, a aVar) {
            super("Media does not support uuid: null");
        }
    }

    /* renamed from: g */
    public static List<DrmInitData.SchemeData> m1441g(DrmInitData drmInitData, UUID uuid, boolean z) {
        ArrayList arrayList = new ArrayList(drmInitData.f9263g);
        for (int i2 = 0; i2 < drmInitData.f9263g; i2++) {
            DrmInitData.SchemeData schemeData = drmInitData.f9260c[i2];
            if ((schemeData.m4050e(null) || (C2399v.f6329c.equals(null) && schemeData.m4050e(C2399v.f6328b))) && (schemeData.f9268h != null || z)) {
                arrayList.add(schemeData);
            }
        }
        return arrayList;
    }

    @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
    @Nullable
    /* renamed from: a */
    public Class<T> mo1442a(DrmInitData drmInitData) {
        if (!mo1446e(drmInitData)) {
            return null;
        }
        Objects.requireNonNull(null);
        throw null;
    }

    @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
    /* renamed from: b */
    public final void mo1443b() {
        int i2 = this.f3378b;
        this.f3378b = i2 + 1;
        if (i2 == 0) {
            C4195m.m4771I(true);
            throw null;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
    @Nullable
    /* renamed from: c */
    public InterfaceC1952c<T> mo1444c(Looper looper, int i2) {
        Looper looper2 = this.f3380d;
        C4195m.m4771I(looper2 == null || looper2 == looper);
        this.f3380d = looper;
        Objects.requireNonNull(null);
        throw null;
    }

    @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
    /* renamed from: d */
    public InterfaceC1952c<T> mo1445d(Looper looper, DrmInitData drmInitData) {
        Looper looper2 = this.f3380d;
        C4195m.m4771I(looper2 == null || looper2 == looper);
        this.f3380d = looper;
        if (this.f3381e == null) {
            this.f3381e = new b(looper);
        }
        List<DrmInitData.SchemeData> m1441g = m1441g(drmInitData, null, false);
        if (((ArrayList) m1441g).isEmpty()) {
            new c(null, null);
            throw null;
        }
        C1950a<T> c1950a = this.f3379c;
        if (c1950a != null) {
            c1950a.acquire();
            return c1950a;
        }
        this.f3379c = m1447f(m1441g, false);
        throw null;
    }

    @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
    /* renamed from: e */
    public boolean mo1446e(DrmInitData drmInitData) {
        if (((ArrayList) m1441g(drmInitData, null, true)).isEmpty() && (drmInitData.f9263g != 1 || !drmInitData.f9260c[0].m4050e(C2399v.f6328b))) {
            return false;
        }
        String str = drmInitData.f9262f;
        if (str == null || "cenc".equals(str)) {
            return true;
        }
        return !("cbc1".equals(str) || "cbcs".equals(str) || "cens".equals(str)) || C2344d0.f6035a >= 25;
    }

    /* renamed from: f */
    public final C1950a<T> m1447f(@Nullable List<DrmInitData.SchemeData> list, boolean z) {
        Objects.requireNonNull(null);
        throw null;
    }

    @Override // p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e
    public final void release() {
        int i2 = this.f3378b - 1;
        this.f3378b = i2;
        if (i2 != 0) {
            return;
        }
        Objects.requireNonNull(null);
        throw null;
    }
}
