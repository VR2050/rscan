package p005b.p143g.p144a.p147m.p156v.p157c;

import android.annotation.TargetApi;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.Build;
import android.util.DisplayMetrics;
import androidx.annotation.Nullable;
import com.bumptech.glide.load.ImageHeaderParser;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1570b;
import p005b.p143g.p144a.p147m.EnumC1583o;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t;
import p005b.p143g.p144a.p170s.C1807i;

/* renamed from: b.g.a.m.v.c.n */
/* loaded from: classes.dex */
public final class C1709n {

    /* renamed from: a */
    public static final C1581m<EnumC1570b> f2506a = C1581m.m825a("com.bumptech.glide.load.resource.bitmap.Downsampler.DecodeFormat", EnumC1570b.PREFER_ARGB_8888);

    /* renamed from: b */
    public static final C1581m<EnumC1583o> f2507b = C1581m.m825a("com.bumptech.glide.load.resource.bitmap.Downsampler.PreferredColorSpace", EnumC1583o.SRGB);

    /* renamed from: c */
    public static final C1581m<Boolean> f2508c;

    /* renamed from: d */
    public static final C1581m<Boolean> f2509d;

    /* renamed from: e */
    public static final Set<String> f2510e;

    /* renamed from: f */
    public static final b f2511f;

    /* renamed from: g */
    public static final Set<ImageHeaderParser.ImageType> f2512g;

    /* renamed from: h */
    public static final Queue<BitmapFactory.Options> f2513h;

    /* renamed from: i */
    public final InterfaceC1614d f2514i;

    /* renamed from: j */
    public final DisplayMetrics f2515j;

    /* renamed from: k */
    public final InterfaceC1612b f2516k;

    /* renamed from: l */
    public final List<ImageHeaderParser> f2517l;

    /* renamed from: m */
    public final C1714s f2518m = C1714s.m1017a();

    /* renamed from: b.g.a.m.v.c.n$a */
    public class a implements b {
        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1709n.b
        /* renamed from: a */
        public void mo985a(InterfaceC1614d interfaceC1614d, Bitmap bitmap) {
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1709n.b
        /* renamed from: b */
        public void mo986b() {
        }
    }

    /* renamed from: b.g.a.m.v.c.n$b */
    public interface b {
        /* renamed from: a */
        void mo985a(InterfaceC1614d interfaceC1614d, Bitmap bitmap);

        /* renamed from: b */
        void mo986b();
    }

    static {
        C1581m<AbstractC1708m> c1581m = AbstractC1708m.f2504f;
        Boolean bool = Boolean.FALSE;
        f2508c = C1581m.m825a("com.bumptech.glide.load.resource.bitmap.Downsampler.FixBitmapSize", bool);
        f2509d = C1581m.m825a("com.bumptech.glide.load.resource.bitmap.Downsampler.AllowHardwareDecode", bool);
        f2510e = Collections.unmodifiableSet(new HashSet(Arrays.asList("image/vnd.wap.wbmp", "image/x-ico")));
        f2511f = new a();
        f2512g = Collections.unmodifiableSet(EnumSet.of(ImageHeaderParser.ImageType.JPEG, ImageHeaderParser.ImageType.PNG_A, ImageHeaderParser.ImageType.PNG));
        char[] cArr = C1807i.f2767a;
        f2513h = new ArrayDeque(0);
    }

    public C1709n(List<ImageHeaderParser> list, DisplayMetrics displayMetrics, InterfaceC1614d interfaceC1614d, InterfaceC1612b interfaceC1612b) {
        this.f2517l = list;
        Objects.requireNonNull(displayMetrics, "Argument must not be null");
        this.f2515j = displayMetrics;
        Objects.requireNonNull(interfaceC1614d, "Argument must not be null");
        this.f2514i = interfaceC1614d;
        Objects.requireNonNull(interfaceC1612b, "Argument must not be null");
        this.f2516k = interfaceC1612b;
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:?, code lost:
    
        throw r0;
     */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.Bitmap m1005d(p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t r4, android.graphics.BitmapFactory.Options r5, p005b.p143g.p144a.p147m.p156v.p157c.C1709n.b r6, p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d r7) {
        /*
            boolean r0 = r5.inJustDecodeBounds
            if (r0 != 0) goto La
            r6.mo986b()
            r4.mo1021c()
        La:
            int r0 = r5.outWidth
            int r1 = r5.outHeight
            java.lang.String r2 = r5.outMimeType
            java.util.concurrent.locks.Lock r3 = p005b.p143g.p144a.p147m.p156v.p157c.C1694b0.f2472e
            r3.lock()
            android.graphics.Bitmap r4 = r4.mo1020b(r5)     // Catch: java.lang.Throwable -> L1d java.lang.IllegalArgumentException -> L1f
            r3.unlock()
            return r4
        L1d:
            r4 = move-exception
            goto L40
        L1f:
            r3 = move-exception
            java.io.IOException r0 = m1010i(r3, r0, r1, r2, r5)     // Catch: java.lang.Throwable -> L1d
            java.lang.String r1 = "Downsampler"
            r2 = 3
            android.util.Log.isLoggable(r1, r2)     // Catch: java.lang.Throwable -> L1d
            android.graphics.Bitmap r1 = r5.inBitmap     // Catch: java.lang.Throwable -> L1d
            if (r1 == 0) goto L3f
            r7.mo870d(r1)     // Catch: java.lang.Throwable -> L1d java.io.IOException -> L3e
            r1 = 0
            r5.inBitmap = r1     // Catch: java.lang.Throwable -> L1d java.io.IOException -> L3e
            android.graphics.Bitmap r4 = m1005d(r4, r5, r6, r7)     // Catch: java.lang.Throwable -> L1d java.io.IOException -> L3e
            java.util.concurrent.locks.Lock r5 = p005b.p143g.p144a.p147m.p156v.p157c.C1694b0.f2472e
            r5.unlock()
            return r4
        L3e:
            throw r0     // Catch: java.lang.Throwable -> L1d
        L3f:
            throw r0     // Catch: java.lang.Throwable -> L1d
        L40:
            java.util.concurrent.locks.Lock r5 = p005b.p143g.p144a.p147m.p156v.p157c.C1694b0.f2472e
            r5.unlock()
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p156v.p157c.C1709n.m1005d(b.g.a.m.v.c.t, android.graphics.BitmapFactory$Options, b.g.a.m.v.c.n$b, b.g.a.m.t.c0.d):android.graphics.Bitmap");
    }

    @Nullable
    @TargetApi(19)
    /* renamed from: e */
    public static String m1006e(Bitmap bitmap) {
        if (bitmap == null) {
            return null;
        }
        StringBuilder m586H = C1499a.m586H(" (");
        m586H.append(bitmap.getAllocationByteCount());
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        String sb = m586H.toString();
        StringBuilder m586H2 = C1499a.m586H("[");
        m586H2.append(bitmap.getWidth());
        m586H2.append("x");
        m586H2.append(bitmap.getHeight());
        m586H2.append("] ");
        m586H2.append(bitmap.getConfig());
        m586H2.append(sb);
        return m586H2.toString();
    }

    /* renamed from: f */
    public static int m1007f(double d2) {
        if (d2 > 1.0d) {
            d2 = 1.0d / d2;
        }
        return (int) Math.round(d2 * 2.147483647E9d);
    }

    /* renamed from: g */
    public static int[] m1008g(InterfaceC1715t interfaceC1715t, BitmapFactory.Options options, b bVar, InterfaceC1614d interfaceC1614d) {
        options.inJustDecodeBounds = true;
        m1005d(interfaceC1715t, options, bVar, interfaceC1614d);
        options.inJustDecodeBounds = false;
        return new int[]{options.outWidth, options.outHeight};
    }

    /* renamed from: h */
    public static boolean m1009h(int i2) {
        return i2 == 90 || i2 == 270;
    }

    /* renamed from: i */
    public static IOException m1010i(IllegalArgumentException illegalArgumentException, int i2, int i3, String str, BitmapFactory.Options options) {
        StringBuilder m589K = C1499a.m589K("Exception decoding bitmap, outWidth: ", i2, ", outHeight: ", i3, ", outMimeType: ");
        m589K.append(str);
        m589K.append(", inBitmap: ");
        m589K.append(m1006e(options.inBitmap));
        return new IOException(m589K.toString(), illegalArgumentException);
    }

    /* renamed from: j */
    public static void m1011j(BitmapFactory.Options options) {
        options.inTempStorage = null;
        options.inDither = false;
        options.inScaled = false;
        options.inSampleSize = 1;
        options.inPreferredConfig = null;
        options.inJustDecodeBounds = false;
        options.inDensity = 0;
        options.inTargetDensity = 0;
        if (Build.VERSION.SDK_INT >= 26) {
            options.inPreferredColorSpace = null;
            options.outColorSpace = null;
            options.outConfig = null;
        }
        options.outWidth = 0;
        options.outHeight = 0;
        options.outMimeType = null;
        options.inBitmap = null;
        options.inMutable = true;
    }

    /* renamed from: k */
    public static int m1012k(double d2) {
        return (int) (d2 + 0.5d);
    }

    /* renamed from: a */
    public final InterfaceC1655w<Bitmap> m1013a(InterfaceC1715t interfaceC1715t, int i2, int i3, C1582n c1582n, b bVar) {
        Queue<BitmapFactory.Options> queue;
        BitmapFactory.Options poll;
        BitmapFactory.Options options;
        byte[] bArr = (byte[]) this.f2516k.mo863d(65536, byte[].class);
        synchronized (C1709n.class) {
            queue = f2513h;
            synchronized (queue) {
                poll = queue.poll();
            }
            if (poll == null) {
                poll = new BitmapFactory.Options();
                m1011j(poll);
            }
            options = poll;
        }
        options.inTempStorage = bArr;
        EnumC1570b enumC1570b = (EnumC1570b) c1582n.m827a(f2506a);
        EnumC1583o enumC1583o = (EnumC1583o) c1582n.m827a(f2507b);
        AbstractC1708m abstractC1708m = (AbstractC1708m) c1582n.m827a(AbstractC1708m.f2504f);
        boolean booleanValue = ((Boolean) c1582n.m827a(f2508c)).booleanValue();
        C1581m<Boolean> c1581m = f2509d;
        try {
            C1699e m995b = C1699e.m995b(m1015c(interfaceC1715t, options, abstractC1708m, enumC1570b, enumC1583o, c1582n.m827a(c1581m) != null && ((Boolean) c1582n.m827a(c1581m)).booleanValue(), i2, i3, booleanValue, bVar), this.f2514i);
            m1011j(options);
            synchronized (queue) {
                queue.offer(options);
            }
            this.f2516k.put(bArr);
            return m995b;
        } catch (Throwable th) {
            m1011j(options);
            Queue<BitmapFactory.Options> queue2 = f2513h;
            synchronized (queue2) {
                queue2.offer(options);
                this.f2516k.put(bArr);
                throw th;
            }
        }
    }

    /* renamed from: b */
    public InterfaceC1655w<Bitmap> m1014b(InputStream inputStream, int i2, int i3, C1582n c1582n, b bVar) {
        return m1013a(new InterfaceC1715t.a(inputStream, this.f2517l, this.f2516k), i2, i3, c1582n, bVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:115:0x030c  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x029c  */
    /* JADX WARN: Removed duplicated region for block: B:126:0x02a2  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x019b  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0197  */
    /* JADX WARN: Removed duplicated region for block: B:69:0x02d2  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x02df  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x02dc  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x02eb  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0328  */
    /* JADX WARN: Removed duplicated region for block: B:92:0x033c  */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final android.graphics.Bitmap m1015c(p005b.p143g.p144a.p147m.p156v.p157c.InterfaceC1715t r25, android.graphics.BitmapFactory.Options r26, p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m r27, p005b.p143g.p144a.p147m.EnumC1570b r28, p005b.p143g.p144a.p147m.EnumC1583o r29, boolean r30, int r31, int r32, boolean r33, p005b.p143g.p144a.p147m.p156v.p157c.C1709n.b r34) {
        /*
            Method dump skipped, instructions count: 1054
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p156v.p157c.C1709n.m1015c(b.g.a.m.v.c.t, android.graphics.BitmapFactory$Options, b.g.a.m.v.c.m, b.g.a.m.b, b.g.a.m.o, boolean, int, int, boolean, b.g.a.m.v.c.n$b):android.graphics.Bitmap");
    }
}
