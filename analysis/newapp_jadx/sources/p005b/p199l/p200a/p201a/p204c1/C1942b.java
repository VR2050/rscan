package p005b.p199l.p200a.p201a.p204c1;

import android.annotation.TargetApi;
import android.media.MediaCodec;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.c1.b */
/* loaded from: classes.dex */
public final class C1942b {

    /* renamed from: a */
    public byte[] f3289a;

    /* renamed from: b */
    public int[] f3290b;

    /* renamed from: c */
    public int[] f3291c;

    /* renamed from: d */
    public final MediaCodec.CryptoInfo f3292d;

    /* renamed from: e */
    public final b f3293e;

    @TargetApi(24)
    /* renamed from: b.l.a.a.c1.b$b */
    public static final class b {

        /* renamed from: a */
        public final MediaCodec.CryptoInfo f3294a;

        /* renamed from: b */
        public final MediaCodec.CryptoInfo.Pattern f3295b = new MediaCodec.CryptoInfo.Pattern(0, 0);

        public b(MediaCodec.CryptoInfo cryptoInfo, a aVar) {
            this.f3294a = cryptoInfo;
        }
    }

    public C1942b() {
        MediaCodec.CryptoInfo cryptoInfo = new MediaCodec.CryptoInfo();
        this.f3292d = cryptoInfo;
        this.f3293e = C2344d0.f6035a >= 24 ? new b(cryptoInfo, null) : null;
    }
}
