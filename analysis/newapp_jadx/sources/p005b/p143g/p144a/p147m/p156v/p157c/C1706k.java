package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import androidx.annotation.NonNull;
import java.security.MessageDigest;
import java.util.concurrent.locks.Lock;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.c.k */
/* loaded from: classes.dex */
public class C1706k extends AbstractC1701f {

    /* renamed from: b */
    public static final byte[] f2493b = "com.bumptech.glide.load.resource.bitmap.CircleCrop.1".getBytes(InterfaceC1579k.f1988a);

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        return obj instanceof C1706k;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        return 1101716364;
    }

    @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1701f
    public Bitmap transform(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap, int i2, int i3) {
        Paint paint = C1694b0.f2468a;
        int min = Math.min(i2, i3);
        float f2 = min;
        float f3 = f2 / 2.0f;
        float width = bitmap.getWidth();
        float height = bitmap.getHeight();
        float max = Math.max(f2 / width, f2 / height);
        float f4 = width * max;
        float f5 = max * height;
        float f6 = (f2 - f4) / 2.0f;
        float f7 = (f2 - f5) / 2.0f;
        RectF rectF = new RectF(f6, f7, f4 + f6, f5 + f7);
        Bitmap m990d = C1694b0.m990d(interfaceC1614d, bitmap);
        Bitmap mo871e = interfaceC1614d.mo871e(min, min, C1694b0.m991e(bitmap));
        mo871e.setHasAlpha(true);
        Lock lock = C1694b0.f2472e;
        lock.lock();
        try {
            Canvas canvas = new Canvas(mo871e);
            canvas.drawCircle(f3, f3, f3, C1694b0.f2469b);
            canvas.drawBitmap(m990d, (Rect) null, rectF, C1694b0.f2470c);
            canvas.setBitmap(null);
            lock.unlock();
            if (!m990d.equals(bitmap)) {
                interfaceC1614d.mo870d(m990d);
            }
            return mo871e;
        } catch (Throwable th) {
            C1694b0.f2472e.unlock();
            throw th;
        }
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(@NonNull MessageDigest messageDigest) {
        messageDigest.update(f2493b);
    }
}
