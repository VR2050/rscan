package com.google.android.exoplayer2.p395ui;

import android.annotation.TargetApi;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.accessibility.CaptioningManager;
import androidx.annotation.Nullable;
import androidx.core.view.ViewCompat;
import java.util.ArrayList;
import java.util.List;
import p005b.p199l.p200a.p201a.p236l1.C2206a;
import p005b.p199l.p200a.p201a.p236l1.C2207b;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2216k;
import p005b.p199l.p200a.p201a.p246n1.C2267e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* loaded from: classes.dex */
public final class SubtitleView extends View implements InterfaceC2216k {

    /* renamed from: c */
    public final List<C2267e> f9698c;

    /* renamed from: e */
    @Nullable
    public List<C2207b> f9699e;

    /* renamed from: f */
    public int f9700f;

    /* renamed from: g */
    public float f9701g;

    /* renamed from: h */
    public boolean f9702h;

    /* renamed from: i */
    public boolean f9703i;

    /* renamed from: j */
    public C2206a f9704j;

    /* renamed from: k */
    public float f9705k;

    public SubtitleView(Context context) {
        this(context, null);
    }

    @TargetApi(19)
    private float getUserCaptionFontScaleV19() {
        return ((CaptioningManager) getContext().getSystemService("captioning")).getFontScale();
    }

    @TargetApi(19)
    private C2206a getUserCaptionStyleV19() {
        CaptioningManager.CaptionStyle userStyle = ((CaptioningManager) getContext().getSystemService("captioning")).getUserStyle();
        if (C2344d0.f6035a < 21) {
            return new C2206a(userStyle.foregroundColor, userStyle.backgroundColor, 0, userStyle.edgeType, userStyle.edgeColor, userStyle.getTypeface());
        }
        return new C2206a(userStyle.hasForegroundColor() ? userStyle.foregroundColor : -1, userStyle.hasBackgroundColor() ? userStyle.backgroundColor : ViewCompat.MEASURED_STATE_MASK, userStyle.hasWindowColor() ? userStyle.windowColor : 0, userStyle.hasEdgeType() ? userStyle.edgeType : 0, userStyle.hasEdgeColor() ? userStyle.edgeColor : -1, userStyle.getTypeface());
    }

    /* renamed from: a */
    public final float m4122a(int i2, float f2, int i3, int i4) {
        float f3;
        if (i2 == 0) {
            f3 = i4;
        } else {
            if (i2 != 1) {
                if (i2 != 2) {
                    return -3.4028235E38f;
                }
                return f2;
            }
            f3 = i3;
        }
        return f2 * f3;
    }

    /* renamed from: b */
    public void m4123b() {
        setStyle((C2344d0.f6035a < 19 || !((CaptioningManager) getContext().getSystemService("captioning")).isEnabled() || isInEditMode()) ? C2206a.f5267a : getUserCaptionStyleV19());
    }

    /* renamed from: c */
    public void m4124c() {
        setFractionalTextSize(((C2344d0.f6035a < 19 || isInEditMode()) ? 1.0f : getUserCaptionFontScaleV19()) * 0.0533f);
    }

    /* JADX WARN: Removed duplicated region for block: B:168:0x03d2  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x0439  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x043b  */
    /* JADX WARN: Removed duplicated region for block: B:189:0x00ad  */
    /* JADX WARN: Removed duplicated region for block: B:190:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01da  */
    @Override // android.view.View
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void dispatchDraw(android.graphics.Canvas r36) {
        /*
            Method dump skipped, instructions count: 1133
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.p395ui.SubtitleView.dispatchDraw(android.graphics.Canvas):void");
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.InterfaceC2216k
    public void onCues(List<C2207b> list) {
        setCues(list);
    }

    public void setApplyEmbeddedFontSizes(boolean z) {
        if (this.f9703i == z) {
            return;
        }
        this.f9703i = z;
        invalidate();
    }

    public void setApplyEmbeddedStyles(boolean z) {
        if (this.f9702h == z && this.f9703i == z) {
            return;
        }
        this.f9702h = z;
        this.f9703i = z;
        invalidate();
    }

    public void setBottomPaddingFraction(float f2) {
        if (this.f9705k == f2) {
            return;
        }
        this.f9705k = f2;
        invalidate();
    }

    public void setCues(@Nullable List<C2207b> list) {
        if (this.f9699e == list) {
            return;
        }
        this.f9699e = list;
        int size = list == null ? 0 : list.size();
        while (this.f9698c.size() < size) {
            this.f9698c.add(new C2267e(getContext()));
        }
        invalidate();
    }

    public void setFractionalTextSize(float f2) {
        if (this.f9700f == 0 && this.f9701g == f2) {
            return;
        }
        this.f9700f = 0;
        this.f9701g = f2;
        invalidate();
    }

    public void setStyle(C2206a c2206a) {
        if (this.f9704j == c2206a) {
            return;
        }
        this.f9704j = c2206a;
        invalidate();
    }

    public SubtitleView(Context context, @Nullable AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f9698c = new ArrayList();
        this.f9700f = 0;
        this.f9701g = 0.0533f;
        this.f9702h = true;
        this.f9703i = true;
        this.f9704j = C2206a.f5267a;
        this.f9705k = 0.08f;
    }
}
