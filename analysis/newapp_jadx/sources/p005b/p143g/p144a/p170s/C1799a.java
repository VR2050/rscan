package p005b.p143g.p144a.p170s;

import androidx.annotation.NonNull;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: b.g.a.s.a */
/* loaded from: classes.dex */
public final class C1799a {

    /* renamed from: a */
    public static final AtomicReference<byte[]> f2744a = new AtomicReference<>();

    /* renamed from: b.g.a.s.a$b */
    public static final class b {

        /* renamed from: a */
        public final int f2747a;

        /* renamed from: b */
        public final int f2748b;

        /* renamed from: c */
        public final byte[] f2749c;

        public b(@NonNull byte[] bArr, int i2, int i3) {
            this.f2749c = bArr;
            this.f2747a = i2;
            this.f2748b = i3;
        }
    }

    @NonNull
    /* renamed from: a */
    public static ByteBuffer m1134a(@NonNull File file) {
        RandomAccessFile randomAccessFile;
        FileChannel fileChannel = null;
        try {
            long length = file.length();
            if (length > 2147483647L) {
                throw new IOException("File too large to map into memory");
            }
            if (length == 0) {
                throw new IOException("File unsuitable for memory mapping");
            }
            randomAccessFile = new RandomAccessFile(file, "r");
            try {
                fileChannel = randomAccessFile.getChannel();
                MappedByteBuffer load = fileChannel.map(FileChannel.MapMode.READ_ONLY, 0L, length).load();
                try {
                    fileChannel.close();
                } catch (IOException unused) {
                }
                try {
                    randomAccessFile.close();
                } catch (IOException unused2) {
                }
                return load;
            } catch (Throwable th) {
                th = th;
                if (fileChannel != null) {
                    try {
                        fileChannel.close();
                    } catch (IOException unused3) {
                    }
                }
                if (randomAccessFile == null) {
                    throw th;
                }
                try {
                    randomAccessFile.close();
                    throw th;
                } catch (IOException unused4) {
                    throw th;
                }
            }
        } catch (Throwable th2) {
            th = th2;
            randomAccessFile = null;
        }
    }

    /* renamed from: b */
    public static void m1135b(@NonNull ByteBuffer byteBuffer, @NonNull File file) {
        RandomAccessFile randomAccessFile;
        byteBuffer.position(0);
        FileChannel fileChannel = null;
        try {
            randomAccessFile = new RandomAccessFile(file, "rw");
            try {
                fileChannel = randomAccessFile.getChannel();
                fileChannel.write(byteBuffer);
                fileChannel.force(false);
                fileChannel.close();
                randomAccessFile.close();
                try {
                    fileChannel.close();
                } catch (IOException unused) {
                }
                try {
                    randomAccessFile.close();
                } catch (IOException unused2) {
                }
            } catch (Throwable th) {
                th = th;
                if (fileChannel != null) {
                    try {
                        fileChannel.close();
                    } catch (IOException unused3) {
                    }
                }
                if (randomAccessFile == null) {
                    throw th;
                }
                try {
                    randomAccessFile.close();
                    throw th;
                } catch (IOException unused4) {
                    throw th;
                }
            }
        } catch (Throwable th2) {
            th = th2;
            randomAccessFile = null;
        }
    }

    /* renamed from: b.g.a.s.a$a */
    public static class a extends InputStream {

        /* renamed from: c */
        @NonNull
        public final ByteBuffer f2745c;

        /* renamed from: e */
        public int f2746e = -1;

        public a(@NonNull ByteBuffer byteBuffer) {
            this.f2745c = byteBuffer;
        }

        @Override // java.io.InputStream
        public int available() {
            return this.f2745c.remaining();
        }

        @Override // java.io.InputStream
        public synchronized void mark(int i2) {
            this.f2746e = this.f2745c.position();
        }

        @Override // java.io.InputStream
        public boolean markSupported() {
            return true;
        }

        @Override // java.io.InputStream
        public int read() {
            if (this.f2745c.hasRemaining()) {
                return this.f2745c.get() & 255;
            }
            return -1;
        }

        @Override // java.io.InputStream
        public synchronized void reset() {
            int i2 = this.f2746e;
            if (i2 == -1) {
                throw new IOException("Cannot reset to unset mark position");
            }
            this.f2745c.position(i2);
        }

        @Override // java.io.InputStream
        public long skip(long j2) {
            if (!this.f2745c.hasRemaining()) {
                return -1L;
            }
            long min = Math.min(j2, available());
            this.f2745c.position((int) (r0.position() + min));
            return min;
        }

        @Override // java.io.InputStream
        public int read(@NonNull byte[] bArr, int i2, int i3) {
            if (!this.f2745c.hasRemaining()) {
                return -1;
            }
            int min = Math.min(i3, available());
            this.f2745c.get(bArr, i2, min);
            return min;
        }
    }
}
