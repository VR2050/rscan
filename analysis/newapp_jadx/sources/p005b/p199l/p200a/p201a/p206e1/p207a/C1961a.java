package p005b.p199l.p200a.p201a.p206e1.p207a;

import android.net.Uri;
import androidx.annotation.Nullable;
import net.butterflytv.rtmp_client.RtmpClient;
import p005b.p199l.p200a.p201a.C1960e0;
import p005b.p199l.p200a.p201a.p248o1.AbstractC2294h;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.e1.a.a */
/* loaded from: classes.dex */
public final class C1961a extends AbstractC2294h {

    /* renamed from: a */
    @Nullable
    public RtmpClient f3389a;

    /* renamed from: b */
    @Nullable
    public Uri f3390b;

    static {
        C1960e0.m1454a("goog.exo.rtmp");
    }

    public C1961a() {
        super(true);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        if (this.f3390b != null) {
            this.f3390b = null;
            transferEnded();
        }
        RtmpClient rtmpClient = this.f3389a;
        if (rtmpClient != null) {
            rtmpClient.nativeClose(rtmpClient.f12974a);
            rtmpClient.f12974a = 0L;
            this.f3389a = null;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f3390b;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        transferInitializing(c2324p);
        RtmpClient rtmpClient = new RtmpClient();
        this.f3389a = rtmpClient;
        String uri = c2324p.f5933a.toString();
        long nativeAlloc = rtmpClient.nativeAlloc();
        rtmpClient.f12974a = nativeAlloc;
        if (nativeAlloc == 0) {
            throw new RtmpClient.C5032a(-2);
        }
        int nativeOpen = rtmpClient.nativeOpen(uri, false, nativeAlloc, 10000, 10000);
        if (nativeOpen != 0) {
            rtmpClient.f12974a = 0L;
            throw new RtmpClient.C5032a(nativeOpen);
        }
        this.f3390b = c2324p.f5933a;
        transferStarted(c2324p);
        return -1L;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        RtmpClient rtmpClient = this.f3389a;
        int i4 = C2344d0.f6035a;
        int nativeRead = rtmpClient.nativeRead(bArr, i2, i3, rtmpClient.f12974a);
        if (nativeRead < 0 && nativeRead != -1) {
            throw new RtmpClient.C5032a(nativeRead);
        }
        if (nativeRead == -1) {
            return -1;
        }
        bytesTransferred(nativeRead);
        return nativeRead;
    }
}
