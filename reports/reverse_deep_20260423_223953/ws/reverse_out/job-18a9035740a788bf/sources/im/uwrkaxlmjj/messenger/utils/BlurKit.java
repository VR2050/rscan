package im.uwrkaxlmjj.messenger.utils;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.renderscript.Allocation;
import android.renderscript.Element;
import android.renderscript.RenderScript;
import android.renderscript.ScriptIntrinsicBlur;
import android.view.View;

/* JADX INFO: loaded from: classes2.dex */
public class BlurKit {
    private static BlurKit instance;
    private RenderScript rs;

    public static void init(Context context) {
        if (instance != null) {
            return;
        }
        BlurKit blurKit = new BlurKit();
        instance = blurKit;
        blurKit.rs = RenderScript.create(context);
    }

    public Bitmap blur(Bitmap src, int radius) {
        Allocation input = Allocation.createFromBitmap(this.rs, src);
        Allocation output = Allocation.createTyped(this.rs, input.getType());
        RenderScript renderScript = this.rs;
        ScriptIntrinsicBlur script = ScriptIntrinsicBlur.create(renderScript, Element.U8_4(renderScript));
        script.setRadius(radius);
        script.setInput(input);
        script.forEach(output);
        output.copyTo(src);
        return src;
    }

    public Bitmap blur(View src, int radius) {
        Bitmap bitmap = getBitmapForView(src, 1.0f);
        return blur(bitmap, radius);
    }

    public Bitmap fastBlur(View src, int radius, float downscaleFactor) {
        Bitmap bitmap = getBitmapForView(src, downscaleFactor);
        return blur(bitmap, radius);
    }

    private Bitmap getBitmapForView(View src, float downscaleFactor) {
        Bitmap bitmap = Bitmap.createBitmap((int) (src.getWidth() * downscaleFactor), (int) (src.getHeight() * downscaleFactor), Bitmap.Config.ARGB_4444);
        Canvas canvas = new Canvas(bitmap);
        Matrix matrix = new Matrix();
        matrix.preScale(downscaleFactor, downscaleFactor);
        canvas.setMatrix(matrix);
        src.draw(canvas);
        return bitmap;
    }

    public static BlurKit getInstance() {
        BlurKit blurKit = instance;
        if (blurKit == null) {
            throw new RuntimeException("BlurKit not initialized!");
        }
        return blurKit;
    }
}
