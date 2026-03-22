package com.angcyo.tablayout;

import android.graphics.drawable.Drawable;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0007\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J*\u0010\u0003\u001a\u00020\u00042\b\u0010\u0005\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u000bH\u0016J*\u0010\f\u001a\u00020\u00042\b\u0010\u0005\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u000bH\u0016J*\u0010\r\u001a\u00020\u00042\b\u0010\u0005\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u000e\u001a\u00020\u000b2\u0006\u0010\u000f\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\u000bH\u0016J*\u0010\u0010\u001a\u00020\u00042\b\u0010\u0005\u001a\u0004\u0018\u00010\u00112\u0006\u0010\u0012\u001a\u00020\u000b2\u0006\u0010\u0013\u001a\u00020\u000b2\u0006\u0010\n\u001a\u00020\u000bH\u0016J\u001a\u0010\u0014\u001a\u00020\u00042\b\u0010\u0005\u001a\u0004\u0018\u00010\u00062\u0006\u0010\u0015\u001a\u00020\bH\u0016¨\u0006\u0016"}, m5311d2 = {"Lcom/angcyo/tablayout/TabGradientCallback;", "", "()V", "onGradientColor", "", "view", "Landroid/view/View;", "startColor", "", "endColor", "percent", "", "onGradientIcoColor", "onGradientScale", "startScale", "endScale", "onGradientTextSize", "Landroid/widget/TextView;", "startTextSize", "endTextSize", "onUpdateIcoColor", "color", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.a0, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class TabGradientCallback {
    /* renamed from: a */
    public void m641a(@Nullable View view, int i2) {
        if (view == null) {
            return;
        }
        if (!(view instanceof TextView)) {
            if (view instanceof ImageView) {
                ImageView imageView = (ImageView) view;
                Drawable drawable = imageView.getDrawable();
                imageView.setImageDrawable(drawable != null ? C4195m.m4778L0(drawable, i2) : null);
                return;
            }
            return;
        }
        Drawable[] drawableArr = new Drawable[4];
        TextView textView = (TextView) view;
        Drawable[] compoundDrawables = textView.getCompoundDrawables();
        Intrinsics.checkNotNullExpressionValue(compoundDrawables, "compoundDrawables");
        int length = compoundDrawables.length;
        int i3 = 0;
        int i4 = 0;
        while (i3 < length) {
            Drawable drawable2 = compoundDrawables[i3];
            i3++;
            int i5 = i4 + 1;
            drawableArr[i4] = drawable2 == null ? null : C4195m.m4778L0(drawable2, i2);
            i4 = i5;
        }
        textView.setCompoundDrawables(drawableArr[0], drawableArr[1], drawableArr[2], drawableArr[3]);
    }
}
