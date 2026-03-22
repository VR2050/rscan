package p005b.p199l.p200a.p201a.p202a1;

import android.annotation.TargetApi;
import android.media.AudioTimestamp;
import android.media.AudioTrack;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.a1.o */
/* loaded from: classes.dex */
public final class C1923o {

    /* renamed from: a */
    @Nullable
    public final a f3084a;

    /* renamed from: b */
    public int f3085b;

    /* renamed from: c */
    public long f3086c;

    /* renamed from: d */
    public long f3087d;

    /* renamed from: e */
    public long f3088e;

    /* renamed from: f */
    public long f3089f;

    @TargetApi(19)
    /* renamed from: b.l.a.a.a1.o$a */
    public static final class a {

        /* renamed from: a */
        public final AudioTrack f3090a;

        /* renamed from: b */
        public final AudioTimestamp f3091b = new AudioTimestamp();

        /* renamed from: c */
        public long f3092c;

        /* renamed from: d */
        public long f3093d;

        /* renamed from: e */
        public long f3094e;

        public a(AudioTrack audioTrack) {
            this.f3090a = audioTrack;
        }
    }

    public C1923o(AudioTrack audioTrack) {
        if (C2344d0.f6035a >= 19) {
            this.f3084a = new a(audioTrack);
            m1269a();
        } else {
            this.f3084a = null;
            m1270b(3);
        }
    }

    /* renamed from: a */
    public void m1269a() {
        if (this.f3084a != null) {
            m1270b(0);
        }
    }

    /* renamed from: b */
    public final void m1270b(int i2) {
        this.f3085b = i2;
        if (i2 == 0) {
            this.f3088e = 0L;
            this.f3089f = -1L;
            this.f3086c = System.nanoTime() / 1000;
            this.f3087d = 5000L;
            return;
        }
        if (i2 == 1) {
            this.f3087d = 5000L;
            return;
        }
        if (i2 == 2 || i2 == 3) {
            this.f3087d = 10000000L;
        } else {
            if (i2 != 4) {
                throw new IllegalStateException();
            }
            this.f3087d = 500000L;
        }
    }
}
