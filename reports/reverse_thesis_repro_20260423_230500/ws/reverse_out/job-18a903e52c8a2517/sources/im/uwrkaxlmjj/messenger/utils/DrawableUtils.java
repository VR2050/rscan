package im.uwrkaxlmjj.messenger.utils;

import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.InsetDrawable;
import android.graphics.drawable.LayerDrawable;
import androidx.core.graphics.drawable.DrawableCompat;
import im.uwrkaxlmjj.messenger.AndroidUtilities;

/* JADX INFO: loaded from: classes2.dex */
public class DrawableUtils {
    public static Bitmap getPicFromBytes(byte[] bytes, BitmapFactory.Options opts) {
        if (bytes != null) {
            return opts != null ? BitmapFactory.decodeByteArray(bytes, 0, bytes.length, opts) : BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
        }
        return null;
    }

    public static Drawable tintDrawable(Drawable drawable, int color) {
        Drawable wrappedDrawable = DrawableCompat.wrap(drawable);
        DrawableCompat.setTint(wrappedDrawable, color);
        return wrappedDrawable;
    }

    public static Drawable tintListDrawable(Drawable drawable, ColorStateList colors) {
        Drawable wrappedDrawable = DrawableCompat.wrap(drawable);
        DrawableCompat.setTintList(wrappedDrawable, colors);
        return wrappedDrawable;
    }

    public static Drawable createLayerDrawable(int innerColor, int strokeColor, float conrnerRadius) {
        return createLayerDrawable(innerColor, strokeColor, conrnerRadius, 0, 0, 0, 0);
    }

    public static Drawable createLayerDrawable(int innerColor, int strokeColor, float conrnerRadius, int insetLeft, int insetTop, int insetRight, int insetBottom) {
        GradientDrawable roundRect = new GradientDrawable();
        roundRect.setShape(0);
        roundRect.setColor(0);
        GradientDrawable innerRect = new GradientDrawable();
        innerRect.setShape(0);
        innerRect.setCornerRadius(conrnerRadius);
        innerRect.setColor(innerColor);
        innerRect.setStroke(AndroidUtilities.dp(0.5f), strokeColor);
        InsetDrawable insetLayer2 = new InsetDrawable((Drawable) innerRect, insetLeft, insetTop, insetRight, insetBottom);
        return new LayerDrawable(new Drawable[]{roundRect, insetLayer2});
    }

    public static Drawable getGradientDrawable(float[] radii, int... colors) {
        GradientDrawable gradientDrawable = new GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, colors);
        gradientDrawable.setShape(0);
        gradientDrawable.setCornerRadii(radii);
        return gradientDrawable;
    }
}
