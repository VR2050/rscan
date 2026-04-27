package io.openinstall.sdk;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.util.Arrays;

/* JADX INFO: loaded from: classes3.dex */
public class cc {
    private static int a(FileChannel fileChannel, long j, ByteBuffer byteBuffer) throws IOException {
        int i;
        int i2 = 0;
        while (byteBuffer.hasRemaining() && (i = fileChannel.read(byteBuffer, j)) != -1) {
            j += (long) i;
            i2 += i;
        }
        return i2;
    }

    private static int a(FileChannel fileChannel, long j, byte[] bArr, int i, int i2) throws IOException {
        ByteBuffer byteBufferWrap = ByteBuffer.wrap(bArr, i, i2);
        int i3 = 0;
        while (i3 < i2) {
            int i4 = fileChannel.read(byteBufferWrap, ((long) i3) + j);
            if (i4 == -1) {
                break;
            }
            i3 += i4;
        }
        return i3;
    }

    public static cb a(FileChannel fileChannel) throws IOException {
        cg cgVarB = b(fileChannel);
        if (cgVarB == null) {
            return null;
        }
        if (cgVarB.f < 32) {
            return new cb(cgVarB);
        }
        byte[] bArr = new byte[24];
        a(fileChannel, cgVarB.f - ((long) 24), bArr, 0, 24);
        long jC = cd.c(bArr, 0, ByteOrder.LITTLE_ENDIAN);
        long jC2 = cd.c(bArr, 8, ByteOrder.LITTLE_ENDIAN);
        long jC3 = cd.c(bArr, 16, ByteOrder.LITTLE_ENDIAN);
        if (jC2 != 2334950737559900225L || jC3 != 3617552046287187010L) {
            return new cb(cgVarB);
        }
        int i = (int) (8 + jC);
        long j = i;
        long j2 = cgVarB.f - j;
        if (i < 32 || j2 < 0) {
            return new cb(cgVarB);
        }
        if (j > 20971520) {
            return new cb(cgVarB);
        }
        ByteBuffer byteBufferAllocate = ByteBuffer.allocate(i - 24);
        byteBufferAllocate.order(ByteOrder.LITTLE_ENDIAN);
        if (a(fileChannel, j2, byteBufferAllocate) != byteBufferAllocate.capacity() || ((ByteBuffer) byteBufferAllocate.flip()).getLong() != jC) {
            return new cb(cgVarB);
        }
        cf cfVar = new cf(j2);
        while (byteBufferAllocate.remaining() >= 12) {
            long j3 = byteBufferAllocate.getLong();
            int i2 = byteBufferAllocate.getInt();
            int i3 = (int) (j3 - 4);
            if (i3 < 0 || i3 > byteBufferAllocate.remaining()) {
                break;
            }
            byte[] bArr2 = new byte[i3];
            byteBufferAllocate.get(bArr2, 0, i3);
            cfVar.a(i2, bArr2);
        }
        return new cb(cfVar, cgVarB);
    }

    private static void a(FileChannel fileChannel, FileChannel fileChannel2, long j, long j2) throws IOException {
        while (j2 > 0) {
            long jTransferTo = fileChannel.transferTo(j, j2, fileChannel2);
            j += jTransferTo;
            j2 -= jTransferTo;
        }
    }

    public static void a(byte[] bArr, File file, File file2) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(file);
        FileOutputStream fileOutputStream = new FileOutputStream(file2);
        try {
            FileChannel channel = fileInputStream.getChannel();
            FileChannel channel2 = fileOutputStream.getChannel();
            cb cbVarA = a(channel);
            channel.position(0L);
            if (cbVarA == null) {
                a(channel, channel2, 0L, channel.size());
                return;
            }
            cbVarA.a(bArr);
            cf cfVarB = cbVarA.b();
            cg cgVarA = cbVarA.a();
            if (cfVarB != null) {
                a(channel, channel2, 0L, cfVarB.b());
                for (ByteBuffer byteBuffer : cfVarB.e()) {
                    while (byteBuffer.hasRemaining()) {
                        channel2.write(byteBuffer);
                    }
                }
                a(channel, channel2, cgVarA.f, cgVarA.h - cgVarA.f);
            } else {
                a(channel, channel2, 0L, cgVarA.h);
            }
            ByteBuffer byteBufferA = cgVarA.a(cfVarB != null ? cfVarB.a() : cgVarA.f);
            while (byteBufferA.hasRemaining()) {
                channel2.write(byteBufferA);
            }
        } finally {
            fileInputStream.close();
            fileOutputStream.close();
        }
    }

    private static cg b(FileChannel fileChannel) throws IOException {
        int i;
        long j;
        byte[] bArr = new byte[128];
        long size = fileChannel.size();
        cg cgVar = null;
        long j2 = 22;
        if (size < 22) {
            return null;
        }
        long j3 = 0;
        long j4 = 106;
        long jMax = Math.max(0L, (size > 65557 ? size - 65557 : 0L) - j4);
        long j5 = size - ((long) 128);
        while (j5 >= jMax) {
            if (j5 < j3) {
                i = (int) (-j5);
                Arrays.fill(bArr, 0, i, (byte) 0);
            } else {
                i = 0;
            }
            long j6 = j5;
            long j7 = j4;
            a(fileChannel, j5 < j3 ? 0L : j5, bArr, i, 128 - i);
            int i2 = 106;
            while (i2 >= 0) {
                if (bArr[i2 + 0] == 80 && bArr[i2 + 1] == 75 && bArr[i2 + 2] == 5 && bArr[i2 + 3] == 6) {
                    int iB = cd.b(bArr, i2 + 20, ByteOrder.LITTLE_ENDIAN) & 65535;
                    long j8 = j6 + ((long) i2);
                    if (j8 + j2 + ((long) iB) == size) {
                        cg cgVar2 = new cg();
                        cgVar2.h = j8;
                        cgVar2.a = cd.b(bArr, i2 + 4, ByteOrder.LITTLE_ENDIAN) & 65535;
                        cgVar2.b = cd.b(bArr, i2 + 6, ByteOrder.LITTLE_ENDIAN) & 65535;
                        cgVar2.c = cd.b(bArr, i2 + 8, ByteOrder.LITTLE_ENDIAN) & 65535;
                        cgVar2.d = 65535 & cd.b(bArr, i2 + 10, ByteOrder.LITTLE_ENDIAN);
                        cgVar2.e = ((long) cd.a(bArr, i2 + 12, ByteOrder.LITTLE_ENDIAN)) & 4294967295L;
                        cgVar2.f = ((long) cd.a(bArr, i2 + 16, ByteOrder.LITTLE_ENDIAN)) & 4294967295L;
                        if (iB > 0) {
                            cgVar2.g = new byte[iB];
                            a(fileChannel, cgVar2.h + 22, cgVar2.g, 0, iB);
                        }
                        return cgVar2;
                    }
                    j = 22;
                } else {
                    j = j2;
                }
                i2--;
                j2 = j;
            }
            j5 = j6 - j7;
            j2 = j2;
            j4 = j7;
            cgVar = null;
            j3 = 0;
        }
        return cgVar;
    }
}
