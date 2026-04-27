package y;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/* JADX INFO: renamed from: y.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0720b extends AbstractC0721c {
    public static C0720b h(ByteBuffer byteBuffer) {
        return i(byteBuffer, new C0720b());
    }

    public static C0720b i(ByteBuffer byteBuffer, C0720b c0720b) {
        byteBuffer.order(ByteOrder.LITTLE_ENDIAN);
        return c0720b.f(byteBuffer.getInt(byteBuffer.position()) + byteBuffer.position(), byteBuffer);
    }

    public C0720b f(int i3, ByteBuffer byteBuffer) {
        g(i3, byteBuffer);
        return this;
    }

    public void g(int i3, ByteBuffer byteBuffer) {
        c(i3, byteBuffer);
    }

    public C0719a j(C0719a c0719a, int i3) {
        int iB = b(6);
        if (iB != 0) {
            return c0719a.f(a(d(iB) + (i3 * 4)), this.f10368b);
        }
        return null;
    }

    public int k() {
        int iB = b(6);
        if (iB != 0) {
            return e(iB);
        }
        return 0;
    }

    public int l() {
        int iB = b(4);
        if (iB != 0) {
            return this.f10368b.getInt(iB + this.f10367a);
        }
        return 0;
    }
}
