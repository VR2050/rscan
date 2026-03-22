package com.luck.picture.lib.tools;

import android.R;
import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.TypedValue;
import androidx.core.content.ContextCompat;

/* loaded from: classes2.dex */
public class AttrsUtils {
    public static ColorStateList getColorStateList(int[] iArr) {
        try {
            return iArr.length == 2 ? new ColorStateList(new int[][]{new int[]{-16842913}, new int[]{R.attr.state_selected}}, iArr) : ColorStateList.valueOf(iArr[0]);
        } catch (Exception e2) {
            e2.printStackTrace();
            return null;
        }
    }

    public static boolean getTypeValueBoolean(Context context, int i2) {
        boolean z = false;
        try {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(new TypedValue().resourceId, new int[]{i2});
            z = obtainStyledAttributes.getBoolean(0, false);
            obtainStyledAttributes.recycle();
            return z;
        } catch (Exception e2) {
            e2.printStackTrace();
            return z;
        }
    }

    public static int getTypeValueColor(Context context, int i2) {
        int i3 = 0;
        try {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(new TypedValue().resourceId, new int[]{i2});
            i3 = obtainStyledAttributes.getColor(0, 0);
            obtainStyledAttributes.recycle();
            return i3;
        } catch (Exception e2) {
            e2.printStackTrace();
            return i3;
        }
    }

    public static ColorStateList getTypeValueColorStateList(Context context, int i2) {
        ColorStateList colorStateList = null;
        try {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(new TypedValue().resourceId, new int[]{i2});
            colorStateList = obtainStyledAttributes.getColorStateList(0);
            obtainStyledAttributes.recycle();
            return colorStateList;
        } catch (Exception e2) {
            e2.printStackTrace();
            return colorStateList;
        }
    }

    public static Drawable getTypeValueDrawable(Context context, int i2, int i3) {
        Drawable drawable = null;
        try {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(new TypedValue().resourceId, new int[]{i2});
            drawable = obtainStyledAttributes.getDrawable(0);
            obtainStyledAttributes.recycle();
        } catch (Exception e2) {
            e2.printStackTrace();
        }
        return drawable == null ? ContextCompat.getDrawable(context, i3) : drawable;
    }

    public static float getTypeValueSize(Context context, int i2) {
        float f2 = 0.0f;
        try {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(new TypedValue().resourceId, new int[]{i2});
            f2 = obtainStyledAttributes.getDimensionPixelSize(0, 0);
            obtainStyledAttributes.recycle();
            return f2;
        } catch (Exception e2) {
            e2.printStackTrace();
            return f2;
        }
    }

    public static int getTypeValueSizeForInt(Context context, int i2) {
        int i3 = 0;
        try {
            TypedArray obtainStyledAttributes = context.obtainStyledAttributes(new TypedValue().resourceId, new int[]{i2});
            i3 = obtainStyledAttributes.getDimensionPixelSize(0, 0);
            obtainStyledAttributes.recycle();
            return i3;
        } catch (Exception e2) {
            e2.printStackTrace();
            return i3;
        }
    }
}
