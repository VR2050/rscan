package p005b.p143g.p144a.p147m.p156v.p157c;

import android.media.MediaDataSource;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.p147m.p156v.p157c.C1698d0;

/* renamed from: b.g.a.m.v.c.e0 */
/* loaded from: classes.dex */
public class C1700e0 extends MediaDataSource {

    /* renamed from: c */
    public final /* synthetic */ ByteBuffer f2488c;

    public C1700e0(C1698d0.d dVar, ByteBuffer byteBuffer) {
        this.f2488c = byteBuffer;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @Override // android.media.MediaDataSource
    public long getSize() {
        return this.f2488c.limit();
    }

    @Override // android.media.MediaDataSource
    public int readAt(long j2, byte[] bArr, int i2, int i3) {
        if (j2 >= this.f2488c.limit()) {
            return -1;
        }
        this.f2488c.position((int) j2);
        int min = Math.min(i3, this.f2488c.remaining());
        this.f2488c.get(bArr, i2, min);
        return min;
    }
}
