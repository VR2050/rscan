package com.angcyo.tablayout;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.TextPaint;
import android.text.TextUtils;
import android.view.Gravity;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000N\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b&\n\u0002\u0010\u000e\n\u0002\b\u000e\n\u0002\u0010\u0007\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002J\u0010\u0010S\u001a\u00020T2\u0006\u0010U\u001a\u00020VH\u0016J\b\u0010W\u001a\u00020\nH\u0016J\b\u0010X\u001a\u00020\nH\u0016J\u001a\u0010Y\u001a\u00020T2\u0006\u0010Z\u001a\u00020[2\b\u0010\\\u001a\u0004\u0018\u00010]H\u0016R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000eR\u001a\u0010\u000f\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0010\u0010\f\"\u0004\b\u0011\u0010\u000eR\u001a\u0010\u0012\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0013\u0010\f\"\u0004\b\u0014\u0010\u000eR\u001a\u0010\u0015\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0016\u0010\f\"\u0004\b\u0017\u0010\u000eR\u001a\u0010\u0018\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0019\u0010\f\"\u0004\b\u001a\u0010\u000eR\u001a\u0010\u001b\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001c\u0010\f\"\u0004\b\u001d\u0010\u000eR\u001a\u0010\u001e\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001f\u0010\f\"\u0004\b \u0010\u000eR\u001a\u0010!\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\"\u0010\f\"\u0004\b#\u0010\u000eR\u001a\u0010$\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b%\u0010\f\"\u0004\b&\u0010\u000eR\u001a\u0010'\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b(\u0010\f\"\u0004\b)\u0010\u000eR\u001a\u0010*\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b+\u0010\f\"\u0004\b,\u0010\u000eR\u001a\u0010-\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b.\u0010\f\"\u0004\b/\u0010\u000eR\u001c\u00100\u001a\u0004\u0018\u000101X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b2\u00103\"\u0004\b4\u00105R\u001a\u00106\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b7\u0010\f\"\u0004\b8\u0010\u000eR\u001a\u00109\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b:\u0010\f\"\u0004\b;\u0010\u000eR\u001a\u0010<\u001a\u00020\nX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b=\u0010\f\"\u0004\b>\u0010\u000eR$\u0010A\u001a\u00020@2\u0006\u0010?\u001a\u00020@@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bB\u0010C\"\u0004\bD\u0010ER\u0011\u0010F\u001a\u00020G¢\u0006\b\n\u0000\u001a\u0004\bH\u0010IR\u0011\u0010J\u001a\u00020\u00048F¢\u0006\u0006\u001a\u0004\bJ\u0010\u0006R\u0011\u0010K\u001a\u00020\n8F¢\u0006\u0006\u001a\u0004\bL\u0010\fR\u0011\u0010M\u001a\u00020\n8F¢\u0006\u0006\u001a\u0004\bN\u0010\fR\u0011\u0010O\u001a\u00020@8F¢\u0006\u0006\u001a\u0004\bP\u0010CR\u0011\u0010Q\u001a\u00020@8F¢\u0006\u0006\u001a\u0004\bR\u0010C¨\u0006^"}, m5311d2 = {"Lcom/angcyo/tablayout/DslBadgeDrawable;", "Lcom/angcyo/tablayout/DslGradientDrawable;", "()V", "badgeAutoCircle", "", "getBadgeAutoCircle", "()Z", "setBadgeAutoCircle", "(Z)V", "badgeCircleOffsetX", "", "getBadgeCircleOffsetX", "()I", "setBadgeCircleOffsetX", "(I)V", "badgeCircleOffsetY", "getBadgeCircleOffsetY", "setBadgeCircleOffsetY", "badgeCircleRadius", "getBadgeCircleRadius", "setBadgeCircleRadius", "badgeGravity", "getBadgeGravity", "setBadgeGravity", "badgeMinHeight", "getBadgeMinHeight", "setBadgeMinHeight", "badgeMinWidth", "getBadgeMinWidth", "setBadgeMinWidth", "badgeOffsetX", "getBadgeOffsetX", "setBadgeOffsetX", "badgeOffsetY", "getBadgeOffsetY", "setBadgeOffsetY", "badgePaddingBottom", "getBadgePaddingBottom", "setBadgePaddingBottom", "badgePaddingLeft", "getBadgePaddingLeft", "setBadgePaddingLeft", "badgePaddingRight", "getBadgePaddingRight", "setBadgePaddingRight", "badgePaddingTop", "getBadgePaddingTop", "setBadgePaddingTop", "badgeText", "", "getBadgeText", "()Ljava/lang/String;", "setBadgeText", "(Ljava/lang/String;)V", "badgeTextColor", "getBadgeTextColor", "setBadgeTextColor", "badgeTextOffsetX", "getBadgeTextOffsetX", "setBadgeTextOffsetX", "badgeTextOffsetY", "getBadgeTextOffsetY", "setBadgeTextOffsetY", "value", "", "badgeTextSize", "getBadgeTextSize", "()F", "setBadgeTextSize", "(F)V", "dslGravity", "Lcom/angcyo/tablayout/DslGravity;", "getDslGravity", "()Lcom/angcyo/tablayout/DslGravity;", "isCircle", "maxHeight", "getMaxHeight", "maxWidth", "getMaxWidth", "textHeight", "getTextHeight", "textWidth", "getTextWidth", "draw", "", "canvas", "Landroid/graphics/Canvas;", "getIntrinsicHeight", "getIntrinsicWidth", "initAttribute", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.e, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslBadgeDrawable extends DslGradientDrawable {

    /* renamed from: A */
    public int f1529A;

    /* renamed from: B */
    public int f1530B;

    /* renamed from: C */
    public int f1531C;

    /* renamed from: D */
    public int f1532D;

    /* renamed from: E */
    public int f1533E;

    /* renamed from: t */
    @Nullable
    public String f1539t;

    /* renamed from: x */
    public int f1543x;

    /* renamed from: y */
    public int f1544y;

    /* renamed from: z */
    public int f1545z;

    /* renamed from: q */
    @NotNull
    public final DslGravity f1536q = new DslGravity();

    /* renamed from: r */
    public int f1537r = 17;

    /* renamed from: s */
    public int f1538s = -1;

    /* renamed from: u */
    public float f1540u = C4195m.m4797b0() * 12;

    /* renamed from: v */
    public boolean f1541v = true;

    /* renamed from: w */
    public int f1542w = C4195m.m4801d0() * 4;

    /* renamed from: F */
    public int f1534F = -2;

    /* renamed from: G */
    public int f1535G = -2;

    @Metadata(m5310d1 = {"\u0000\u0010\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0003H\n¢\u0006\u0002\b\u0005"}, m5311d2 = {"<anonymous>", "", "centerX", "", "centerY", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.e$a */
    public static final class a extends Lambda implements Function2<Integer, Integer, Unit> {

        /* renamed from: e */
        public final /* synthetic */ DslGravity f1547e;

        /* renamed from: f */
        public final /* synthetic */ Canvas f1548f;

        /* renamed from: g */
        public final /* synthetic */ float f1549g;

        /* renamed from: h */
        public final /* synthetic */ float f1550h;

        /* renamed from: i */
        public final /* synthetic */ float f1551i;

        /* renamed from: j */
        public final /* synthetic */ float f1552j;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(DslGravity dslGravity, Canvas canvas, float f2, float f3, float f4, float f5) {
            super(2);
            this.f1547e = dslGravity;
            this.f1548f = canvas;
            this.f1549g = f2;
            this.f1550h = f3;
            this.f1551i = f4;
            this.f1552j = f5;
        }

        @Override // kotlin.jvm.functions.Function2
        public Unit invoke(Integer num, Integer num2) {
            float f2;
            int intValue = num.intValue();
            int intValue2 = num2.intValue();
            if (DslBadgeDrawable.this.m654n()) {
                DslBadgeDrawable.this.m649f().setColor(DslBadgeDrawable.this.f1554c);
                int i2 = this.f1547e.f1569b;
                float f3 = intValue;
                if ((i2 & 112) == 16 && (Gravity.getAbsoluteGravity(i2, 0) & 7) == 1) {
                    f2 = intValue2;
                } else {
                    DslGravity dslGravity = this.f1547e;
                    f3 += dslGravity.f1577j;
                    f2 = intValue2 + dslGravity.f1578k;
                }
                DslBadgeDrawable.this.m649f().setColor(DslBadgeDrawable.this.f1554c);
                this.f1548f.drawCircle(f3, f2, r1.f1542w, DslBadgeDrawable.this.m649f());
                DslBadgeDrawable dslBadgeDrawable = DslBadgeDrawable.this;
                if (dslBadgeDrawable.f1556e > 0 && dslBadgeDrawable.f1555d != 0) {
                    float strokeWidth = dslBadgeDrawable.m649f().getStrokeWidth();
                    Paint.Style style = DslBadgeDrawable.this.m649f().getStyle();
                    DslBadgeDrawable.this.m649f().setColor(DslBadgeDrawable.this.f1555d);
                    DslBadgeDrawable.this.m649f().setStrokeWidth(DslBadgeDrawable.this.f1556e);
                    DslBadgeDrawable.this.m649f().setStyle(Paint.Style.STROKE);
                    this.f1548f.drawCircle(f3, f2, r3.f1542w, DslBadgeDrawable.this.m649f());
                    DslBadgeDrawable.this.m649f().setStrokeWidth(strokeWidth);
                    DslBadgeDrawable.this.m649f().setStyle(style);
                }
            } else {
                DslBadgeDrawable.this.m649f().setColor(DslBadgeDrawable.this.f1538s);
                float f4 = intValue;
                float f5 = 2;
                float f6 = f4 - (this.f1549g / f5);
                float f7 = intValue2;
                float f8 = (this.f1550h / f5) + f7;
                DslGravity dslGravity2 = this.f1547e;
                int i3 = dslGravity2.f1575h;
                int i4 = dslGravity2.f1576i;
                DslBadgeDrawable dslBadgeDrawable2 = DslBadgeDrawable.this;
                if (dslBadgeDrawable2.f1541v) {
                    String str = dslBadgeDrawable2.f1539t;
                    if (str != null && str.length() == 1) {
                        DslBadgeDrawable dslBadgeDrawable3 = DslBadgeDrawable.this;
                        if (dslBadgeDrawable3.f1554c != 0) {
                            dslBadgeDrawable3.m649f().setColor(DslBadgeDrawable.this.f1554c);
                            this.f1548f.drawCircle(f4, f7, Math.max(DslBadgeDrawable.this.m653m(), DslBadgeDrawable.this.m652l()) / f5, DslBadgeDrawable.this.m649f());
                        }
                        DslBadgeDrawable.this.m649f().setColor(DslBadgeDrawable.this.f1538s);
                        Canvas canvas = this.f1548f;
                        String str2 = DslBadgeDrawable.this.f1539t;
                        Intrinsics.checkNotNull(str2);
                        Objects.requireNonNull(DslBadgeDrawable.this);
                        float f9 = 0;
                        float descent = f8 - DslBadgeDrawable.this.m649f().descent();
                        Objects.requireNonNull(DslBadgeDrawable.this);
                        canvas.drawText(str2, f6 + f9, descent + f9, DslBadgeDrawable.this.m649f());
                    }
                }
                Drawable drawable = DslBadgeDrawable.this.f1565n;
                if (drawable != null) {
                    float f10 = this.f1551i;
                    float f11 = this.f1552j;
                    Canvas canvas2 = this.f1548f;
                    drawable.setBounds(i3, i4, (int) (i3 + f10), (int) (i4 + f11));
                    drawable.draw(canvas2);
                }
                DslBadgeDrawable.this.m649f().setColor(DslBadgeDrawable.this.f1538s);
                Canvas canvas3 = this.f1548f;
                String str22 = DslBadgeDrawable.this.f1539t;
                Intrinsics.checkNotNull(str22);
                Objects.requireNonNull(DslBadgeDrawable.this);
                float f92 = 0;
                float descent2 = f8 - DslBadgeDrawable.this.m649f().descent();
                Objects.requireNonNull(DslBadgeDrawable.this);
                canvas3.drawText(str22, f6 + f92, descent2 + f92, DslBadgeDrawable.this.m649f());
            }
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x002c  */
    /* JADX WARN: Removed duplicated region for block: B:18:0x0053  */
    /* JADX WARN: Removed duplicated region for block: B:21:0x0070  */
    /* JADX WARN: Removed duplicated region for block: B:24:0x0081  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0093  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x00af  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x00f6  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x0107  */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0112  */
    /* JADX WARN: Removed duplicated region for block: B:49:0x015b  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x018d  */
    /* JADX WARN: Removed duplicated region for block: B:73:0x0147  */
    /* JADX WARN: Removed duplicated region for block: B:74:0x010b  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x00fe  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00b4  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x0083  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x005c  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x0036  */
    @Override // com.angcyo.tablayout.DslGradientDrawable, android.graphics.drawable.Drawable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void draw(@org.jetbrains.annotations.NotNull android.graphics.Canvas r18) {
        /*
            Method dump skipped, instructions count: 442
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.angcyo.tablayout.DslBadgeDrawable.draw(android.graphics.Canvas):void");
    }

    @Override // com.angcyo.tablayout.AbsDslDrawable, android.graphics.drawable.Drawable
    public int getIntrinsicHeight() {
        int m652l;
        if (m654n()) {
            m652l = this.f1542w * 2;
        } else {
            if (this.f1541v) {
                String str = this.f1539t;
                boolean z = false;
                if (str != null && str.length() == 1) {
                    z = true;
                }
                if (z) {
                    m652l = Math.max(m653m(), m652l());
                }
            }
            m652l = m652l();
        }
        return Math.max(this.f1534F, m652l);
    }

    @Override // com.angcyo.tablayout.AbsDslDrawable, android.graphics.drawable.Drawable
    public int getIntrinsicWidth() {
        int m653m;
        if (m654n()) {
            m653m = this.f1542w * 2;
        } else {
            if (this.f1541v) {
                String str = this.f1539t;
                boolean z = false;
                if (str != null && str.length() == 1) {
                    z = true;
                }
                if (z) {
                    m653m = Math.max(m653m(), m652l());
                }
            }
            m653m = m653m();
        }
        return Math.max(this.f1535G, m653m);
    }

    /* renamed from: l */
    public final int m652l() {
        TextPaint m649f = m649f();
        int descent = (int) (m649f == null ? 0.0f : m649f.descent() - m649f.ascent());
        Drawable drawable = this.f1565n;
        return Math.max(descent, drawable == null ? 0 : drawable.getMinimumHeight()) + this.f1532D + this.f1533E;
    }

    /* renamed from: m */
    public final int m653m() {
        TextPaint m649f = m649f();
        String str = this.f1539t;
        float f2 = 0.0f;
        if (!TextUtils.isEmpty(str) && m649f != null) {
            f2 = m649f.measureText(str);
        }
        int i2 = (int) f2;
        Drawable drawable = this.f1565n;
        return Math.max(i2, drawable == null ? 0 : drawable.getMinimumWidth()) + this.f1530B + this.f1531C;
    }

    /* renamed from: n */
    public final boolean m654n() {
        return TextUtils.isEmpty(this.f1539t);
    }
}
