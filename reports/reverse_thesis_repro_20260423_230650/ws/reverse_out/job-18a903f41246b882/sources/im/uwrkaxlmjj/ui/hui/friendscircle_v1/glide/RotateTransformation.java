package im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapShader;
import android.graphics.Canvas;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Shader;
import com.bumptech.glide.Glide;
import com.bumptech.glide.load.Transformation;
import com.bumptech.glide.load.engine.Resource;
import com.bumptech.glide.load.engine.bitmap_recycle.BitmapPool;
import com.bumptech.glide.load.resource.bitmap.BitmapResource;
import java.security.MessageDigest;

/* JADX INFO: loaded from: classes5.dex */
public class RotateTransformation implements Transformation<Bitmap> {
    private boolean isLeftBottom;
    private boolean isLeftTop;
    private boolean isRightBotoom;
    private boolean isRightTop;
    private BitmapPool mBitmapPool;
    private float radius;

    public void setNeedCorner(boolean leftTop, boolean rightTop, boolean leftBottom, boolean rightBottom) {
        this.isLeftTop = leftTop;
        this.isRightTop = rightTop;
        this.isLeftBottom = leftBottom;
        this.isRightBotoom = rightBottom;
    }

    public RotateTransformation(Context context, float radius) {
        this.mBitmapPool = Glide.get(context).getBitmapPool();
        this.radius = radius;
    }

    @Override // com.bumptech.glide.load.Transformation
    public Resource<Bitmap> transform(Context context, Resource<Bitmap> resource, int outWidth, int outHeight) {
        int finalHeight;
        int finalWidth;
        Bitmap source = resource.get();
        if (outWidth > outHeight) {
            float scale = outHeight / outWidth;
            finalWidth = source.getWidth();
            finalHeight = (int) (source.getWidth() * scale);
            if (finalHeight > source.getHeight()) {
                float scale2 = outWidth / outHeight;
                finalHeight = source.getHeight();
                finalWidth = (int) (source.getHeight() * scale2);
            }
        } else if (outWidth < outHeight) {
            float scale3 = outWidth / outHeight;
            finalHeight = source.getHeight();
            finalWidth = (int) (source.getHeight() * scale3);
            if (finalWidth > source.getWidth()) {
                float scale4 = outHeight / outWidth;
                finalWidth = source.getWidth();
                finalHeight = (int) (source.getWidth() * scale4);
            }
        } else {
            finalHeight = source.getHeight();
            finalWidth = finalHeight;
        }
        this.radius *= finalHeight / outHeight;
        Bitmap outBitmap = this.mBitmapPool.get(finalWidth, finalHeight, Bitmap.Config.ARGB_8888);
        if (outBitmap == null) {
            outBitmap = Bitmap.createBitmap(finalWidth, finalHeight, Bitmap.Config.ARGB_8888);
        }
        Canvas canvas = new Canvas(outBitmap);
        Paint paint = new Paint();
        BitmapShader shader = new BitmapShader(source, Shader.TileMode.CLAMP, Shader.TileMode.CLAMP);
        int width = (source.getWidth() - finalWidth) / 2;
        int height = (source.getHeight() - finalHeight) / 2;
        if (width != 0 || height != 0) {
            Matrix matrix = new Matrix();
            matrix.setTranslate(-width, -height);
            shader.setLocalMatrix(matrix);
        }
        paint.setShader(shader);
        paint.setAntiAlias(true);
        RectF rectF = new RectF(0.0f, 0.0f, canvas.getWidth(), canvas.getHeight());
        float f = this.radius;
        canvas.drawRoundRect(rectF, f, f, paint);
        if (!this.isLeftTop) {
            float f2 = this.radius;
            canvas.drawRect(0.0f, 0.0f, f2, f2, paint);
        }
        if (!this.isRightTop) {
            canvas.drawRect(canvas.getWidth() - this.radius, 0.0f, canvas.getWidth(), this.radius, paint);
        }
        if (!this.isLeftBottom) {
            float height2 = canvas.getHeight();
            float f3 = this.radius;
            canvas.drawRect(0.0f, height2 - f3, f3, canvas.getHeight(), paint);
        }
        if (!this.isRightBotoom) {
            canvas.drawRect(canvas.getWidth() - this.radius, canvas.getHeight() - this.radius, canvas.getWidth(), canvas.getHeight(), paint);
        }
        return BitmapResource.obtain(outBitmap, this.mBitmapPool);
    }

    @Override // com.bumptech.glide.load.Key
    public void updateDiskCacheKey(MessageDigest messageDigest) {
    }
}
