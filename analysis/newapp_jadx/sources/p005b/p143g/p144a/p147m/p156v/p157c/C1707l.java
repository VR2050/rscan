package p005b.p143g.p144a.p147m.p156v.p157c;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.core.view.InputDeviceCompat;
import com.bumptech.glide.load.ImageHeaderParser;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Objects;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;

/* renamed from: b.g.a.m.v.c.l */
/* loaded from: classes.dex */
public final class C1707l implements ImageHeaderParser {

    /* renamed from: a */
    public static final byte[] f2494a = "Exif\u0000\u0000".getBytes(Charset.forName("UTF-8"));

    /* renamed from: b */
    public static final int[] f2495b = {0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8};

    /* renamed from: b.g.a.m.v.c.l$a */
    public static final class a implements c {

        /* renamed from: a */
        public final ByteBuffer f2496a;

        public a(ByteBuffer byteBuffer) {
            this.f2496a = byteBuffer;
            byteBuffer.order(ByteOrder.BIG_ENDIAN);
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public int getUInt16() {
            return (getUInt8() << 8) | getUInt8();
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public short getUInt8() {
            if (this.f2496a.remaining() >= 1) {
                return (short) (this.f2496a.get() & 255);
            }
            throw new c.a();
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public int read(byte[] bArr, int i2) {
            int min = Math.min(i2, this.f2496a.remaining());
            if (min == 0) {
                return -1;
            }
            this.f2496a.get(bArr, 0, min);
            return min;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public long skip(long j2) {
            int min = (int) Math.min(this.f2496a.remaining(), j2);
            ByteBuffer byteBuffer = this.f2496a;
            byteBuffer.position(byteBuffer.position() + min);
            return min;
        }
    }

    /* renamed from: b.g.a.m.v.c.l$b */
    public static final class b {

        /* renamed from: a */
        public final ByteBuffer f2497a;

        public b(byte[] bArr, int i2) {
            this.f2497a = (ByteBuffer) ByteBuffer.wrap(bArr).order(ByteOrder.BIG_ENDIAN).limit(i2);
        }

        /* renamed from: a */
        public short m1001a(int i2) {
            if (this.f2497a.remaining() - i2 >= 2) {
                return this.f2497a.getShort(i2);
            }
            return (short) -1;
        }

        /* renamed from: b */
        public int m1002b(int i2) {
            if (this.f2497a.remaining() - i2 >= 4) {
                return this.f2497a.getInt(i2);
            }
            return -1;
        }
    }

    /* renamed from: b.g.a.m.v.c.l$c */
    public interface c {

        /* renamed from: b.g.a.m.v.c.l$c$a */
        public static final class a extends IOException {
            private static final long serialVersionUID = 1;

            public a() {
                super("Unexpectedly reached end of a file");
            }
        }

        int getUInt16();

        short getUInt8();

        int read(byte[] bArr, int i2);

        long skip(long j2);
    }

    /* renamed from: b.g.a.m.v.c.l$d */
    public static final class d implements c {

        /* renamed from: a */
        public final InputStream f2498a;

        public d(InputStream inputStream) {
            this.f2498a = inputStream;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public int getUInt16() {
            return (getUInt8() << 8) | getUInt8();
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public short getUInt8() {
            int read = this.f2498a.read();
            if (read != -1) {
                return (short) read;
            }
            throw new c.a();
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public int read(byte[] bArr, int i2) {
            int i3 = 0;
            int i4 = 0;
            while (i3 < i2 && (i4 = this.f2498a.read(bArr, i3, i2 - i3)) != -1) {
                i3 += i4;
            }
            if (i3 == 0 && i4 == -1) {
                throw new c.a();
            }
            return i3;
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1707l.c
        public long skip(long j2) {
            if (j2 < 0) {
                return 0L;
            }
            long j3 = j2;
            while (j3 > 0) {
                long skip = this.f2498a.skip(j3);
                if (skip <= 0) {
                    if (this.f2498a.read() == -1) {
                        break;
                    }
                    skip = 1;
                }
                j3 -= skip;
            }
            return j2 - j3;
        }
    }

    @Override // com.bumptech.glide.load.ImageHeaderParser
    @NonNull
    /* renamed from: a */
    public ImageHeaderParser.ImageType mo996a(@NonNull ByteBuffer byteBuffer) {
        Objects.requireNonNull(byteBuffer, "Argument must not be null");
        return m999d(new a(byteBuffer));
    }

    @Override // com.bumptech.glide.load.ImageHeaderParser
    @NonNull
    /* renamed from: b */
    public ImageHeaderParser.ImageType mo997b(@NonNull InputStream inputStream) {
        Objects.requireNonNull(inputStream, "Argument must not be null");
        return m999d(new d(inputStream));
    }

    @Override // com.bumptech.glide.load.ImageHeaderParser
    /* renamed from: c */
    public int mo998c(@NonNull InputStream inputStream, @NonNull InterfaceC1612b interfaceC1612b) {
        int i2;
        Objects.requireNonNull(inputStream, "Argument must not be null");
        d dVar = new d(inputStream);
        Objects.requireNonNull(interfaceC1612b, "Argument must not be null");
        try {
            int uInt16 = dVar.getUInt16();
            if (!((uInt16 & 65496) == 65496 || uInt16 == 19789 || uInt16 == 18761)) {
                Log.isLoggable("DfltImageHeaderParser", 3);
                return -1;
            }
            while (true) {
                if (dVar.getUInt8() == 255) {
                    short uInt8 = dVar.getUInt8();
                    if (uInt8 == 218) {
                        break;
                    }
                    if (uInt8 != 217) {
                        i2 = dVar.getUInt16() - 2;
                        if (uInt8 == 225) {
                            break;
                        }
                        long j2 = i2;
                        if (dVar.skip(j2) != j2) {
                            Log.isLoggable("DfltImageHeaderParser", 3);
                            break;
                        }
                    } else {
                        Log.isLoggable("DfltImageHeaderParser", 3);
                        break;
                    }
                } else {
                    Log.isLoggable("DfltImageHeaderParser", 3);
                    break;
                }
            }
            i2 = -1;
            if (i2 == -1) {
                Log.isLoggable("DfltImageHeaderParser", 3);
                return -1;
            }
            byte[] bArr = (byte[]) interfaceC1612b.mo863d(i2, byte[].class);
            try {
                int m1000e = m1000e(dVar, bArr, i2);
                interfaceC1612b.put(bArr);
                return m1000e;
            } catch (Throwable th) {
                interfaceC1612b.put(bArr);
                throw th;
            }
        } catch (c.a unused) {
            return -1;
        }
    }

    @NonNull
    /* renamed from: d */
    public final ImageHeaderParser.ImageType m999d(c cVar) {
        try {
            int uInt16 = cVar.getUInt16();
            if (uInt16 == 65496) {
                return ImageHeaderParser.ImageType.JPEG;
            }
            int uInt8 = (uInt16 << 8) | cVar.getUInt8();
            if (uInt8 == 4671814) {
                return ImageHeaderParser.ImageType.GIF;
            }
            int uInt82 = (uInt8 << 8) | cVar.getUInt8();
            if (uInt82 == -1991225785) {
                cVar.skip(21L);
                try {
                    return cVar.getUInt8() >= 3 ? ImageHeaderParser.ImageType.PNG_A : ImageHeaderParser.ImageType.PNG;
                } catch (c.a unused) {
                    return ImageHeaderParser.ImageType.PNG;
                }
            }
            if (uInt82 != 1380533830) {
                return ImageHeaderParser.ImageType.UNKNOWN;
            }
            cVar.skip(4L);
            if (((cVar.getUInt16() << 16) | cVar.getUInt16()) != 1464156752) {
                return ImageHeaderParser.ImageType.UNKNOWN;
            }
            int uInt162 = (cVar.getUInt16() << 16) | cVar.getUInt16();
            if ((uInt162 & InputDeviceCompat.SOURCE_ANY) != 1448097792) {
                return ImageHeaderParser.ImageType.UNKNOWN;
            }
            int i2 = uInt162 & 255;
            if (i2 == 88) {
                cVar.skip(4L);
                return (cVar.getUInt8() & 16) != 0 ? ImageHeaderParser.ImageType.WEBP_A : ImageHeaderParser.ImageType.WEBP;
            }
            if (i2 != 76) {
                return ImageHeaderParser.ImageType.WEBP;
            }
            cVar.skip(4L);
            return (cVar.getUInt8() & 8) != 0 ? ImageHeaderParser.ImageType.WEBP_A : ImageHeaderParser.ImageType.WEBP;
        } catch (c.a unused2) {
            return ImageHeaderParser.ImageType.UNKNOWN;
        }
    }

    /* renamed from: e */
    public final int m1000e(c cVar, byte[] bArr, int i2) {
        ByteOrder byteOrder;
        if (cVar.read(bArr, i2) != i2) {
            Log.isLoggable("DfltImageHeaderParser", 3);
            return -1;
        }
        boolean z = bArr != null && i2 > f2494a.length;
        if (z) {
            int i3 = 0;
            while (true) {
                byte[] bArr2 = f2494a;
                if (i3 >= bArr2.length) {
                    break;
                }
                if (bArr[i3] != bArr2[i3]) {
                    z = false;
                    break;
                }
                i3++;
            }
        }
        if (!z) {
            Log.isLoggable("DfltImageHeaderParser", 3);
            return -1;
        }
        b bVar = new b(bArr, i2);
        short m1001a = bVar.m1001a(6);
        if (m1001a == 18761) {
            byteOrder = ByteOrder.LITTLE_ENDIAN;
        } else if (m1001a != 19789) {
            Log.isLoggable("DfltImageHeaderParser", 3);
            byteOrder = ByteOrder.BIG_ENDIAN;
        } else {
            byteOrder = ByteOrder.BIG_ENDIAN;
        }
        bVar.f2497a.order(byteOrder);
        int m1002b = bVar.m1002b(10) + 6;
        short m1001a2 = bVar.m1001a(m1002b);
        for (int i4 = 0; i4 < m1001a2; i4++) {
            int i5 = (i4 * 12) + m1002b + 2;
            if (bVar.m1001a(i5) == 274) {
                short m1001a3 = bVar.m1001a(i5 + 2);
                if (m1001a3 < 1 || m1001a3 > 12) {
                    Log.isLoggable("DfltImageHeaderParser", 3);
                } else {
                    int m1002b2 = bVar.m1002b(i5 + 4);
                    if (m1002b2 < 0) {
                        Log.isLoggable("DfltImageHeaderParser", 3);
                    } else {
                        Log.isLoggable("DfltImageHeaderParser", 3);
                        int i6 = m1002b2 + f2495b[m1001a3];
                        if (i6 > 4) {
                            Log.isLoggable("DfltImageHeaderParser", 3);
                        } else {
                            int i7 = i5 + 8;
                            if (i7 < 0 || i7 > bVar.f2497a.remaining()) {
                                Log.isLoggable("DfltImageHeaderParser", 3);
                            } else {
                                if (i6 >= 0 && i6 + i7 <= bVar.f2497a.remaining()) {
                                    return bVar.m1001a(i7);
                                }
                                Log.isLoggable("DfltImageHeaderParser", 3);
                            }
                        }
                    }
                }
            }
        }
        return -1;
    }
}
