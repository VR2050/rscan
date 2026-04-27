package io.openinstall.sdk;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ListIterator;

/* JADX INFO: loaded from: classes3.dex */
public class cf implements Cloneable {
    private final long a;
    private final List<ce<Integer, a>> b = new ArrayList();

    private static class a {
        byte[] a;

        public a(byte[] bArr) {
            this.a = bArr;
        }

        public byte[] a() {
            byte[] bArr = this.a;
            int length = bArr.length - 12;
            byte[] bArr2 = new byte[length];
            System.arraycopy(bArr, 12, bArr2, 0, length);
            return bArr2;
        }
    }

    public cf(long j) {
        this.a = j;
    }

    private byte[] a(int i) {
        for (ce<Integer, a> ceVar : this.b) {
            if (ceVar.a.intValue() == i) {
                return ceVar.b.a();
            }
        }
        return null;
    }

    private void b(int i) {
        Iterator<ce<Integer, a>> it = this.b.iterator();
        while (it.hasNext()) {
            if (it.next().a.intValue() == i) {
                it.remove();
            }
        }
    }

    public long a() {
        return this.a + c();
    }

    public void a(int i, byte[] bArr) {
        byte[] bArr2 = new byte[bArr.length + 8 + 4];
        ByteBuffer byteBufferOrder = ByteBuffer.wrap(bArr2).order(ByteOrder.LITTLE_ENDIAN);
        byteBufferOrder.putLong(r0 - 8).putInt(i);
        byteBufferOrder.put(bArr);
        ce<Integer, a> ceVar = new ce<>(Integer.valueOf(i), new a(bArr2));
        ListIterator<ce<Integer, a>> listIterator = this.b.listIterator();
        while (listIterator.hasNext()) {
            if (listIterator.next().a.intValue() == i) {
                listIterator.set(ceVar);
                return;
            }
        }
        this.b.add(ceVar);
    }

    public void a(byte[] bArr) {
        if (bArr == null) {
            b(987894612);
        } else {
            a(987894612, bArr);
        }
    }

    public long b() {
        return this.a;
    }

    public long c() {
        Iterator<ce<Integer, a>> it = this.b.iterator();
        long length = 32;
        while (it.hasNext()) {
            length += (long) it.next().b.a.length;
        }
        return length;
    }

    public byte[] d() {
        return a(987894612);
    }

    public ByteBuffer[] e() {
        ByteBuffer[] byteBufferArr = new ByteBuffer[this.b.size() + 2];
        long jC = c() - 8;
        byteBufferArr[0] = (ByteBuffer) ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(jC).flip();
        Iterator<ce<Integer, a>> it = this.b.iterator();
        int i = 1;
        while (it.hasNext()) {
            byteBufferArr[i] = ByteBuffer.wrap(it.next().b.a);
            i++;
        }
        byteBufferArr[i] = (ByteBuffer) ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).putLong(jC).putLong(2334950737559900225L).putLong(3617552046287187010L).flip();
        return byteBufferArr;
    }

    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public cf clone() {
        cf cfVar = new cf(this.a);
        for (ce<Integer, a> ceVar : this.b) {
            cfVar.b.add(new ce<>(ceVar.a, ceVar.b));
        }
        return cfVar;
    }
}
