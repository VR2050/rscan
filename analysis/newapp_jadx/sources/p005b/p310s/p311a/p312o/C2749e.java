package p005b.p310s.p311a.p312o;

import android.graphics.Point;
import android.hardware.Camera;
import android.os.Handler;

/* renamed from: b.s.a.o.e */
/* loaded from: classes2.dex */
public final class C2749e implements Camera.PreviewCallback {

    /* renamed from: a */
    public static final String f7547a = C2749e.class.getSimpleName();

    /* renamed from: b */
    public final C2746b f7548b;

    /* renamed from: c */
    public Handler f7549c;

    /* renamed from: d */
    public int f7550d;

    public C2749e(C2746b c2746b) {
        this.f7548b = c2746b;
    }

    @Override // android.hardware.Camera.PreviewCallback
    public void onPreviewFrame(byte[] bArr, Camera camera) {
        Point point = this.f7548b.f7525e;
        Handler handler = this.f7549c;
        if (point == null || handler == null) {
            return;
        }
        handler.obtainMessage(this.f7550d, point.x, point.y, bArr).sendToTarget();
        this.f7549c = null;
    }
}
