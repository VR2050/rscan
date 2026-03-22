package p005b.p143g.p144a.p147m.p156v.p157c;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.drawable.Animatable;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Drawable;
import android.util.Log;
import androidx.annotation.Nullable;
import java.util.concurrent.locks.Lock;
import p005b.p143g.p144a.p147m.p150t.InterfaceC1655w;
import p005b.p143g.p144a.p147m.p150t.p151c0.C1615e;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;

/* renamed from: b.g.a.m.v.c.o */
/* loaded from: classes.dex */
public final class C1710o {

    /* renamed from: a */
    public static final InterfaceC1614d f2519a = new a();

    /* renamed from: b.g.a.m.v.c.o$a */
    public class a extends C1615e {
        @Override // p005b.p143g.p144a.p147m.p150t.p151c0.C1615e, p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d
        /* renamed from: d */
        public void mo870d(Bitmap bitmap) {
        }
    }

    @Nullable
    /* renamed from: a */
    public static InterfaceC1655w<Bitmap> m1016a(InterfaceC1614d interfaceC1614d, Drawable drawable, int i2, int i3) {
        Drawable current = drawable.getCurrent();
        boolean z = false;
        Bitmap bitmap = null;
        if (current instanceof BitmapDrawable) {
            bitmap = ((BitmapDrawable) current).getBitmap();
        } else if (!(current instanceof Animatable)) {
            if (i2 != Integer.MIN_VALUE || current.getIntrinsicWidth() > 0) {
                if (i3 != Integer.MIN_VALUE || current.getIntrinsicHeight() > 0) {
                    if (current.getIntrinsicWidth() > 0) {
                        i2 = current.getIntrinsicWidth();
                    }
                    if (current.getIntrinsicHeight() > 0) {
                        i3 = current.getIntrinsicHeight();
                    }
                    Lock lock = C1694b0.f2472e;
                    lock.lock();
                    Bitmap mo871e = interfaceC1614d.mo871e(i2, i3, Bitmap.Config.ARGB_8888);
                    try {
                        Canvas canvas = new Canvas(mo871e);
                        current.setBounds(0, 0, i2, i3);
                        current.draw(canvas);
                        canvas.setBitmap(null);
                        lock.unlock();
                        bitmap = mo871e;
                    } catch (Throwable th) {
                        lock.unlock();
                        throw th;
                    }
                } else if (Log.isLoggable("DrawableToBitmap", 5)) {
                    String str = "Unable to draw " + current + " to Bitmap with Target.SIZE_ORIGINAL because the Drawable has no intrinsic height";
                }
            } else if (Log.isLoggable("DrawableToBitmap", 5)) {
                String str2 = "Unable to draw " + current + " to Bitmap with Target.SIZE_ORIGINAL because the Drawable has no intrinsic width";
            }
            z = true;
        }
        if (!z) {
            interfaceC1614d = f2519a;
        }
        return C1699e.m995b(bitmap, interfaceC1614d);
    }
}
