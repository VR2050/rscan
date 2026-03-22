package p005b.p199l.p200a.p201a.p202a1;

import android.os.Handler;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p202a1.InterfaceC1921m;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.a1.m */
/* loaded from: classes.dex */
public interface InterfaceC1921m {

    /* renamed from: b.l.a.a.a1.m$a */
    public static final class a {

        /* renamed from: a */
        @Nullable
        public final Handler f3082a;

        /* renamed from: b */
        @Nullable
        public final InterfaceC1921m f3083b;

        public a(@Nullable Handler handler, @Nullable InterfaceC1921m interfaceC1921m) {
            if (interfaceC1921m != null) {
                Objects.requireNonNull(handler);
            } else {
                handler = null;
            }
            this.f3082a = handler;
            this.f3083b = interfaceC1921m;
        }

        /* renamed from: a */
        public void m1268a(final C1944d c1944d) {
            synchronized (c1944d) {
            }
            Handler handler = this.f3082a;
            if (handler != null) {
                handler.post(new Runnable() { // from class: b.l.a.a.a1.f
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC1921m.a aVar = InterfaceC1921m.a.this;
                        C1944d c1944d2 = c1944d;
                        Objects.requireNonNull(aVar);
                        synchronized (c1944d2) {
                        }
                        InterfaceC1921m interfaceC1921m = aVar.f3083b;
                        int i2 = C2344d0.f6035a;
                        interfaceC1921m.onAudioDisabled(c1944d2);
                    }
                });
            }
        }
    }

    void onAudioDecoderInitialized(String str, long j2, long j3);

    void onAudioDisabled(C1944d c1944d);

    void onAudioEnabled(C1944d c1944d);

    void onAudioInputFormatChanged(Format format);

    void onAudioSessionId(int i2);

    void onAudioSinkUnderrun(int i2, long j2, long j3);
}
