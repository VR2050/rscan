package com.jbzd.media.movecartoons.view.image;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.renderscript.RSRuntimeException;
import androidx.annotation.NonNull;
import java.security.MessageDigest;
import p005b.p143g.p144a.p147m.p150t.p151c0.InterfaceC1614d;
import p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1701f;
import p005b.p143g.p144a.p147m.p156v.p157c.C1694b0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* loaded from: classes2.dex */
public class GlideBlurTransformer extends AbstractC1701f {
    private Context context;
    private int radius;
    private double sampling;

    public GlideBlurTransformer(Context context, int i2, double d2) {
        this.context = context;
        this.radius = i2;
        this.sampling = d2;
    }

    private Bitmap blurCrop(InterfaceC1614d interfaceC1614d, Bitmap bitmap) {
        if (bitmap == null) {
            return null;
        }
        int width = bitmap.getWidth();
        int height = bitmap.getHeight();
        double d2 = this.sampling;
        Bitmap mo871e = interfaceC1614d.mo871e((int) (width / d2), (int) (height / d2), Bitmap.Config.ARGB_8888);
        Canvas canvas = new Canvas(mo871e);
        double d3 = this.sampling;
        canvas.scale(1.0f / ((float) d3), 1.0f / ((float) d3));
        Paint paint = new Paint();
        paint.setFlags(2);
        canvas.drawBitmap(bitmap, 0.0f, 0.0f, paint);
        try {
            C2354n.m2491l(this.context, mo871e, this.radius);
            return mo871e;
        } catch (RSRuntimeException unused) {
            return C2354n.m2494m(mo871e, this.radius, true);
        }
    }

    @Override // p005b.p143g.p144a.p147m.p156v.p157c.AbstractC1701f
    public Bitmap transform(@NonNull InterfaceC1614d interfaceC1614d, @NonNull Bitmap bitmap, int i2, int i3) {
        return blurCrop(interfaceC1614d, C1694b0.m988b(interfaceC1614d, bitmap, i2, i3));
    }

    @Override // p005b.p143g.p144a.p147m.InterfaceC1579k
    public void updateDiskCacheKey(MessageDigest messageDigest) {
    }
}
