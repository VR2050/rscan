package com.jbzd.media.movecartoons.p396ui.index.view;

import android.content.Context;
import android.graphics.Color;
import android.graphics.LinearGradient;
import android.graphics.Shader;
import android.util.AttributeSet;
import android.util.TypedValue;
import android.widget.TextView;
import kotlin.Metadata;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u00012\u00020\u0002B\u001b\u0012\b\u0010\u0007\u001a\u0004\u0018\u00010\u0006\u0012\b\u0010\t\u001a\u0004\u0018\u00010\b¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/view/BloodColorText;", "Landroid/widget/TextView;", "Lcom/jbzd/media/movecartoons/ui/index/view/BloodColor;", "", "setBloodColor", "()V", "Landroid/content/Context;", "context", "Landroid/util/AttributeSet;", "attrs", "<init>", "(Landroid/content/Context;Landroid/util/AttributeSet;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BloodColorText extends TextView implements BloodColor {
    public BloodColorText(@Nullable Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
    }

    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.index.view.BloodColor
    public void setBloodColor() {
        getPaint().setShader(new LinearGradient(0.0f, 0.0f, 0.0f, TypedValue.applyDimension(2, 18.0f, getResources().getDisplayMetrics()), Color.parseColor("#FF0000"), Color.parseColor("#ffffff"), Shader.TileMode.REPEAT));
    }
}
