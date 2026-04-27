package y;

import java.nio.ByteBuffer;

/* JADX INFO: renamed from: y.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0721c {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    protected int f10367a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    protected ByteBuffer f10368b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private int f10369c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f10370d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    d f10371e = d.a();

    protected int a(int i3) {
        return i3 + this.f10368b.getInt(i3);
    }

    protected int b(int i3) {
        if (i3 < this.f10370d) {
            return this.f10368b.getShort(this.f10369c + i3);
        }
        return 0;
    }

    protected void c(int i3, ByteBuffer byteBuffer) {
        this.f10368b = byteBuffer;
        if (byteBuffer == null) {
            this.f10367a = 0;
            this.f10369c = 0;
            this.f10370d = 0;
        } else {
            this.f10367a = i3;
            int i4 = i3 - byteBuffer.getInt(i3);
            this.f10369c = i4;
            this.f10370d = this.f10368b.getShort(i4);
        }
    }

    protected int d(int i3) {
        int i4 = i3 + this.f10367a;
        return i4 + this.f10368b.getInt(i4) + 4;
    }

    protected int e(int i3) {
        int i4 = i3 + this.f10367a;
        return this.f10368b.getInt(i4 + this.f10368b.getInt(i4));
    }
}
