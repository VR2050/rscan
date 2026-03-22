package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.RectF;
import android.graphics.Shader;
import androidx.annotation.NonNull;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.concurrent.locks.Lock;
import p005b.p143g.p144a.p147m.InterfaceC1579k;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p170s.C1807i;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.g.a.m.v.c.z */
/* loaded from: classes.dex */
public final class C1721z extends AbstractC1701f {

    /* renamed from: b */
    public static final byte[] f2548b = "com.bumptech.glide.load.resource.bitmap.RoundedCorners".getBytes(InterfaceC1579k.f1988a);

    /* renamed from: c */
    public final int f2549c;

    public C1721z(int i2) {
        C4195m.m4763E(i2 > 0, "roundingRadius must be greater than 0.");
        this.f2549c = i2;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public boolean equals(Object obj) {
        return (obj instanceof C1721z) && this.f2549c == ((C1721z) obj).f2549c;
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public int hashCode() {
        int i2 = this.f2549c;
        char[] cArr = C1807i.f2767a;
        return ((i2 + 527) * 31) - 569625254;
    }

    @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1701f
    public Bitmap transform(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap, int i2, int i3) {
        int i4 = this.f2549c;
        Paint paint = C1694b0.f2468a;
        C4195m.m4763E(i4 > 0, "roundingRadius must be greater than 0.");
        Bitmap.Config m991e = C1694b0.m991e(bitmap);
        Bitmap m990d = C1694b0.m990d(interfaceC1614d, bitmap);
        Bitmap mo871e = interfaceC1614d.mo871e(m990d.getWidth(), m990d.getHeight(), m991e);
        mo871e.setHasAlpha(true);
        Shader.TileMode tileMode = Shader.TileMode.CLAMP;
        BitmapShader bitmapShader = new BitmapShader(m990d, tileMode, tileMode);
        Paint paint2 = new Paint();
        paint2.setAntiAlias(true);
        paint2.setShader(bitmapShader);
        RectF rectF = new RectF(0.0f, 0.0f, mo871e.getWidth(), mo871e.getHeight());
        Lock lock = C1694b0.f2472e;
        lock.lock();
        try {
            Canvas canvas = new Canvas(mo871e);
            canvas.drawColor(0, PorterDuff.Mode.CLEAR);
            float f2 = i4;
            canvas.drawRoundRect(rectF, f2, f2, paint2);
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
        messageDigest.update(f2548b);
        messageDigest.update(ByteBuffer.allocate(4).putInt(this.f2549c).array());
    }
}
