package io.openinstall.sdk;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/* JADX INFO: loaded from: classes3.dex */
public class cg implements Cloneable {
    private static final byte[] i = new byte[0];
    public int a;
    public int b;
    public int c;
    public int d;
    public long e;
    public long f;
    public byte[] g = i;
    public long h;

    public int a() {
        return this.g.length + 22;
    }

    public ByteBuffer a(long j) {
        ByteBuffer byteBufferAllocate = ByteBuffer.allocate(a());
        byteBufferAllocate.order(ByteOrder.LITTLE_ENDIAN);
        byteBufferAllocate.putInt(101010256);
        byteBufferAllocate.putShort((short) this.a);
        byteBufferAllocate.putShort((short) this.b);
        byteBufferAllocate.putShort((short) this.c);
        byteBufferAllocate.putShort((short) this.d);
        byteBufferAllocate.putInt((int) this.e);
        byteBufferAllocate.putInt((int) j);
        byteBufferAllocate.putShort((short) this.g.length);
        byteBufferAllocate.put(this.g);
        byteBufferAllocate.flip();
        return byteBufferAllocate;
    }

    public void a(byte[] bArr) {
        if (bArr == null || bArr.length == 0) {
            bArr = i;
        }
        this.g = bArr;
    }

    /* JADX INFO: renamed from: b, reason: merged with bridge method [inline-methods] */
    public cg clone() {
        try {
            return (cg) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new Error(e);
        }
    }
}
