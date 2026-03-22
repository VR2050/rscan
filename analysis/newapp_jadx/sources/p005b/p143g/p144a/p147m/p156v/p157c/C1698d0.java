package p005b.p143g.p144a.p147m.p156v.p157c;

import android.content.res.AssetFileDescriptor;
import android.graphics.Bitmap;
import android.media.MediaMetadataRetriever;
import android.os.ParcelFileDescriptor;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.C1581m;
import p005b.p143g.p144a.p147m.C1582n;
import p005b.p143g.p144a.p147m.InterfaceC1584p;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.c.d0 */
/* loaded from: classes.dex */
public class C1698d0<T> implements InterfaceC1584p<T, Bitmap> {

    /* renamed from: a */
    public static final C1581m<Long> f2478a = new C1581m<>("com.bumptech.glide.load.resource.bitmap.VideoBitmapDecode.TargetFrame", -1L, new a());

    /* renamed from: b */
    public static final C1581m<Integer> f2479b = new C1581m<>("com.bumptech.glide.load.resource.bitmap.VideoBitmapDecode.FrameOption", 2, new b());

    /* renamed from: c */
    public static final e f2480c = new e();

    /* renamed from: d */
    public final f<T> f2481d;

    /* renamed from: e */
    public final InterfaceC1614d f2482e;

    /* renamed from: f */
    public final e f2483f;

    /* renamed from: b.g.a.m.v.c.d0$a */
    public class a implements C1581m.b<Long> {

        /* renamed from: a */
        public final ByteBuffer f2484a = ByteBuffer.allocate(8);

        @Override // p005b.p143g.p144a.p147m.C1581m.b
        /* renamed from: a */
        public void mo826a(@NonNull byte[] bArr, @NonNull Long l2, @NonNull MessageDigest messageDigest) {
            Long l3 = l2;
            messageDigest.update(bArr);
            synchronized (this.f2484a) {
                this.f2484a.position(0);
                messageDigest.update(this.f2484a.putLong(l3.longValue()).array());
            }
        }
    }

    /* renamed from: b.g.a.m.v.c.d0$b */
    public class b implements C1581m.b<Integer> {

        /* renamed from: a */
        public final ByteBuffer f2485a = ByteBuffer.allocate(4);

        @Override // p005b.p143g.p144a.p147m.C1581m.b
        /* renamed from: a */
        public void mo826a(@NonNull byte[] bArr, @NonNull Integer num, @NonNull MessageDigest messageDigest) {
            Integer num2 = num;
            if (num2 == null) {
                return;
            }
            messageDigest.update(bArr);
            synchronized (this.f2485a) {
                this.f2485a.position(0);
                messageDigest.update(this.f2485a.putInt(num2.intValue()).array());
            }
        }
    }

    /* renamed from: b.g.a.m.v.c.d0$c */
    public static final class c implements f<AssetFileDescriptor> {
        public c(a aVar) {
        }

        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1698d0.f
        /* renamed from: a */
        public void mo994a(MediaMetadataRetriever mediaMetadataRetriever, AssetFileDescriptor assetFileDescriptor) {
            AssetFileDescriptor assetFileDescriptor2 = assetFileDescriptor;
            mediaMetadataRetriever.setDataSource(assetFileDescriptor2.getFileDescriptor(), assetFileDescriptor2.getStartOffset(), assetFileDescriptor2.getLength());
        }
    }

    @RequiresApi(23)
    /* renamed from: b.g.a.m.v.c.d0$d */
    public static final class d implements f<ByteBuffer> {
        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1698d0.f
        /* renamed from: a */
        public void mo994a(MediaMetadataRetriever mediaMetadataRetriever, ByteBuffer byteBuffer) {
            mediaMetadataRetriever.setDataSource(new C1700e0(this, byteBuffer));
        }
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.v.c.d0$e */
    public static class e {
    }

    @VisibleForTesting
    /* renamed from: b.g.a.m.v.c.d0$f */
    public interface f<T> {
        /* renamed from: a */
        void mo994a(MediaMetadataRetriever mediaMetadataRetriever, T t);
    }

    /* renamed from: b.g.a.m.v.c.d0$g */
    public static final class g implements f<ParcelFileDescriptor> {
        @Override // p005b.p143g.p144a.p147m.p156v.p157c.C1698d0.f
        /* renamed from: a */
        public void mo994a(MediaMetadataRetriever mediaMetadataRetriever, ParcelFileDescriptor parcelFileDescriptor) {
            mediaMetadataRetriever.setDataSource(parcelFileDescriptor.getFileDescriptor());
        }
    }

    public C1698d0(InterfaceC1614d interfaceC1614d, f<T> fVar) {
        e eVar = f2480c;
        this.f2482e = interfaceC1614d;
        this.f2481d = fVar;
        this.f2483f = eVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:16:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:19:? A[RETURN, SYNTHETIC] */
    @androidx.annotation.Nullable
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.Bitmap m993c(android.media.MediaMetadataRetriever r9, long r10, int r12, int r13, int r14, p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m r15) {
        /*
            int r0 = android.os.Build.VERSION.SDK_INT
            r1 = 27
            if (r0 < r1) goto L59
            r0 = -2147483648(0xffffffff80000000, float:-0.0)
            if (r13 == r0) goto L59
            if (r14 == r0) goto L59
            b.g.a.m.v.c.m r0 = p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1708m.f2502d
            if (r15 == r0) goto L59
            r0 = 18
            java.lang.String r0 = r9.extractMetadata(r0)     // Catch: java.lang.Throwable -> L53
            int r0 = java.lang.Integer.parseInt(r0)     // Catch: java.lang.Throwable -> L53
            r1 = 19
            java.lang.String r1 = r9.extractMetadata(r1)     // Catch: java.lang.Throwable -> L53
            int r1 = java.lang.Integer.parseInt(r1)     // Catch: java.lang.Throwable -> L53
            r2 = 24
            java.lang.String r2 = r9.extractMetadata(r2)     // Catch: java.lang.Throwable -> L53
            int r2 = java.lang.Integer.parseInt(r2)     // Catch: java.lang.Throwable -> L53
            r3 = 90
            if (r2 == r3) goto L36
            r3 = 270(0x10e, float:3.78E-43)
            if (r2 != r3) goto L39
        L36:
            r8 = r1
            r1 = r0
            r0 = r8
        L39:
            float r13 = r15.mo1004b(r0, r1, r13, r14)     // Catch: java.lang.Throwable -> L53
            float r14 = (float) r0     // Catch: java.lang.Throwable -> L53
            float r14 = r14 * r13
            int r6 = java.lang.Math.round(r14)     // Catch: java.lang.Throwable -> L53
            float r14 = (float) r1     // Catch: java.lang.Throwable -> L53
            float r13 = r13 * r14
            int r7 = java.lang.Math.round(r13)     // Catch: java.lang.Throwable -> L53
            r2 = r9
            r3 = r10
            r5 = r12
            android.graphics.Bitmap r13 = r2.getScaledFrameAtTime(r3, r5, r6, r7)     // Catch: java.lang.Throwable -> L53
            goto L5a
        L53:
            r13 = 3
            java.lang.String r14 = "VideoDecoder"
            android.util.Log.isLoggable(r14, r13)
        L59:
            r13 = 0
        L5a:
            if (r13 != 0) goto L60
            android.graphics.Bitmap r13 = r9.getFrameAtTime(r10, r12)
        L60:
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p143g.p144a.p147m.p156v.p157c.C1698d0.m993c(android.media.MediaMetadataRetriever, long, int, int, int, b.g.a.m.v.c.m):android.graphics.Bitmap");
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: a */
    public boolean mo829a(@NonNull T t, @NonNull C1582n c1582n) {
        return true;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1584p
    /* renamed from: b */
    public InterfaceC1655w<Bitmap> mo830b(@NonNull T t, int i2, int i3, @NonNull C1582n c1582n) {
        long longValue = ((Long) c1582n.m827a(f2478a)).longValue();
        if (longValue < 0 && longValue != -1) {
            throw new IllegalArgumentException(C1499a.m630p("Requested frame must be non-negative, or DEFAULT_FRAME, given: ", longValue));
        }
        Integer num = (Integer) c1582n.m827a(f2479b);
        if (num == null) {
            num = 2;
        }
        AbstractC1708m abstractC1708m = (AbstractC1708m) c1582n.m827a(AbstractC1708m.f2504f);
        if (abstractC1708m == null) {
            abstractC1708m = AbstractC1708m.f2503e;
        }
        AbstractC1708m abstractC1708m2 = abstractC1708m;
        Objects.requireNonNull(this.f2483f);
        MediaMetadataRetriever mediaMetadataRetriever = new MediaMetadataRetriever();
        try {
            try {
                this.f2481d.mo994a(mediaMetadataRetriever, t);
                Bitmap m993c = m993c(mediaMetadataRetriever, longValue, num.intValue(), i2, i3, abstractC1708m2);
                mediaMetadataRetriever.release();
                return C1699e.m995b(m993c, this.f2482e);
            } catch (RuntimeException e2) {
                throw new IOException(e2);
            }
        } catch (Throwable th) {
            mediaMetadataRetriever.release();
            throw th;
        }
    }
}
