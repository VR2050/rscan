package p005b.p199l.p200a.p201a.p251q1;

import android.os.Handler;
import android.view.Surface;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p204c1.C1944d;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p251q1.InterfaceC2386r;

/* renamed from: b.l.a.a.q1.r */
/* loaded from: classes.dex */
public interface InterfaceC2386r {

    /* renamed from: b.l.a.a.q1.r$a */
    public static final class a {

        /* renamed from: a */
        @Nullable
        public final Handler f6268a;

        /* renamed from: b */
        @Nullable
        public final InterfaceC2386r f6269b;

        public a(@Nullable Handler handler, @Nullable InterfaceC2386r interfaceC2386r) {
            if (interfaceC2386r != null) {
                Objects.requireNonNull(handler);
            } else {
                handler = null;
            }
            this.f6268a = handler;
            this.f6269b = interfaceC2386r;
        }

        /* renamed from: a */
        public void m2642a(final int i2, final int i3, final int i4, final float f2) {
            Handler handler = this.f6268a;
            if (handler != null) {
                handler.post(new Runnable() { // from class: b.l.a.a.q1.g
                    @Override // java.lang.Runnable
                    public final void run() {
                        InterfaceC2386r.a aVar = InterfaceC2386r.a.this;
                        int i5 = i2;
                        int i6 = i3;
                        int i7 = i4;
                        float f3 = f2;
                        InterfaceC2386r interfaceC2386r = aVar.f6269b;
                        int i8 = C2344d0.f6035a;
                        interfaceC2386r.onVideoSizeChanged(i5, i6, i7, f3);
                    }
                });
            }
        }
    }

    void onDroppedFrames(int i2, long j2);

    void onRenderedFirstFrame(@Nullable Surface surface);

    void onVideoDecoderInitialized(String str, long j2, long j3);

    void onVideoDisabled(C1944d c1944d);

    void onVideoEnabled(C1944d c1944d);

    void onVideoInputFormatChanged(Format format);

    void onVideoSizeChanged(int i2, int i3, int i4, float f2);
}
