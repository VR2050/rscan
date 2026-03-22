package p005b.p143g.p144a.p147m.p156v.p161g;

import android.content.Context;
import android.graphics.Bitmap;
import android.os.SystemClock;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.VisibleForTesting;
import com.bumptech.glide.load.ImageHeaderParser;
import com.bumptech.glide.load.resource.gif.GifDrawable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import p005b.p143g.p144a.p146l.C1566c;
import p005b.p143g.p144a.p146l.C1567d;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p143g.p144a.p147m.C1574f;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.EnumC1570b;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1612b;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p147m.p156v.C1690b;
import p005b.p143g.p144a.p170s.C1803e;
import p005b.p143g.p144a.p170s.C1807i;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.v.g.a */
/* loaded from: classes.dex */
public class C1731a implements InterfaceC1584p<ByteBuffer, GifDrawable> {

    /* renamed from: a */
    public static final a f2556a = new a();

    /* renamed from: b */
    public static final b f2557b = new b();

    /* renamed from: c */
    public final Context f2558c;

    /* renamed from: d */
    public final List<ImageHeaderParser> f2559d;

    /* renamed from: e */
    public final b f2560e;

    /* renamed from: f */
    public final a f2561f;

    /* renamed from: g */
    public final C1732b f2562g;

    @VisibleForTesting
    /* renamed from: b.g.a.m.v.g.a$a */
    public static class a {
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.v.g.a$b */
    public static class b {

        /* renamed from: a */
        public final Queue<C1567d> f2563a;

        public b() {
            char[] cArr = C1807i.f2767a;
            this.f2563a = new ArrayDeque(0);
        }

        /* renamed from: a */
        public synchronized void m1030a(C1567d c1567d) {
            c1567d.f1946b = null;
            c1567d.f1947c = null;
            this.f2563a.offer(c1567d);
        }
    }

    public C1731a(Context context, List<ImageHeaderParser> list, InterfaceC1614d interfaceC1614d, InterfaceC1612b interfaceC1612b) {
        b bVar = f2557b;
        a aVar = f2556a;
        this.f2558c = context.getApplicationContext();
        this.f2559d = list;
        this.f2561f = aVar;
        this.f2562g = new C1732b(interfaceC1614d, interfaceC1612b);
        this.f2560e = bVar;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull ByteBuffer byteBuffer, @NonNull C1582n c1582n) {
        ByteBuffer byteBuffer2 = byteBuffer;
        if (!((Boolean) c1582n.m827a(C1738h.f2592b)).booleanValue()) {
            if ((byteBuffer2 == null ? ImageHeaderParser.ImageType.UNKNOWN : C4195m.m4813j0(this.f2559d, new C1574f(byteBuffer2))) == ImageHeaderParser.ImageType.GIF) {
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: b */
    public InterfaceC1655w<GifDrawable> mo830b(@NonNull ByteBuffer byteBuffer, int i2, int i3, @NonNull C1582n c1582n) {
        C1567d c1567d;
        ByteBuffer byteBuffer2 = byteBuffer;
        b bVar = this.f2560e;
        synchronized (bVar) {
            C1567d poll = bVar.f2563a.poll();
            if (poll == null) {
                poll = new C1567d();
            }
            c1567d = poll;
            c1567d.f1946b = null;
            Arrays.fill(c1567d.f1945a, (byte) 0);
            c1567d.f1947c = new C1566c();
            c1567d.f1948d = 0;
            ByteBuffer asReadOnlyBuffer = byteBuffer2.asReadOnlyBuffer();
            c1567d.f1946b = asReadOnlyBuffer;
            asReadOnlyBuffer.position(0);
            c1567d.f1946b.order(ByteOrder.LITTLE_ENDIAN);
        }
        try {
            return m1029c(byteBuffer2, i2, i3, c1567d, c1582n);
        } finally {
            this.f2560e.m1030a(c1567d);
        }
    }

    @Nullable
    /* renamed from: c */
    public final C1734d m1029c(ByteBuffer byteBuffer, int i2, int i3, C1567d c1567d, C1582n c1582n) {
        int i4 = C1803e.f2759b;
        long elapsedRealtimeNanos = SystemClock.elapsedRealtimeNanos();
        try {
            C1566c m813b = c1567d.m813b();
            if (m813b.f1935c > 0 && m813b.f1934b == 0) {
                Bitmap.Config config = c1582n.m827a(C1738h.f2591a) == EnumC1570b.PREFER_RGB_565 ? Bitmap.Config.RGB_565 : Bitmap.Config.ARGB_8888;
                int min = Math.min(m813b.f1939g / i3, m813b.f1938f / i2);
                int max = Math.max(1, min == 0 ? 0 : Integer.highestOneBit(min));
                Log.isLoggable("BufferGifDecoder", 2);
                a aVar = this.f2561f;
                C1732b c1732b = this.f2562g;
                Objects.requireNonNull(aVar);
                C1568e c1568e = new C1568e(c1732b, m813b, byteBuffer, max);
                c1568e.m820j(config);
                c1568e.f1960l = (c1568e.f1960l + 1) % c1568e.f1961m.f1935c;
                Bitmap mo804a = c1568e.mo804a();
                if (mo804a == null) {
                    return null;
                }
                C1734d c1734d = new C1734d(new GifDrawable(this.f2558c, c1568e, (C1690b) C1690b.f2459b, i2, i3, mo804a));
                if (Log.isLoggable("BufferGifDecoder", 2)) {
                    C1803e.m1138a(elapsedRealtimeNanos);
                }
                return c1734d;
            }
            if (Log.isLoggable("BufferGifDecoder", 2)) {
                C1803e.m1138a(elapsedRealtimeNanos);
            }
            return null;
        } finally {
            if (Log.isLoggable("BufferGifDecoder", 2)) {
                C1803e.m1138a(elapsedRealtimeNanos);
            }
        }
    }
}
