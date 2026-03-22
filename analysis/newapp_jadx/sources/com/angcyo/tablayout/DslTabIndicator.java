package com.angcyo.tablayout;

import android.content.Context;
import android.content.res.Resources;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import com.angcyo.tablayout.DslTabLayout;
import com.angcyo.tablayout.R$styleable;
import com.jbzd.media.movecartoons.p396ui.index.post.PostHomeFragment;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.jvm.internal.Ref;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import tv.danmaku.ijk.media.player.IjkMediaPlayer;

@Metadata(m5310d1 = {"\u0000j\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\n\n\u0002\u0010\u000b\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b)\n\u0002\u0010\u0007\n\u0002\b\n\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0013\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\b\u0016\u0018\u0000 }2\u00020\u0001:\u0001}B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J\u000e\u0010R\u001a\u00020\u00062\u0006\u0010S\u001a\u00020\u0006J\u0010\u0010T\u001a\u00020U2\u0006\u0010V\u001a\u00020WH\u0016J\u000e\u0010X\u001a\u00020U2\u0006\u0010V\u001a\u00020WJ>\u0010Y\u001a\u00020U2\u0006\u0010Z\u001a\u00020 2\u0006\u0010V\u001a\u00020W2\u0006\u0010[\u001a\u00020\u00062\u0006\u0010\\\u001a\u00020\u00062\u0006\u0010]\u001a\u00020\u00062\u0006\u0010^\u001a\u00020\u00062\u0006\u0010_\u001a\u00020JJF\u0010`\u001a\u00020U2\u0006\u0010Z\u001a\u00020 2\u0006\u0010V\u001a\u00020W2\u0006\u0010[\u001a\u00020\u00062\u0006\u0010\\\u001a\u00020\u00062\u0006\u0010]\u001a\u00020\u00062\u0006\u0010^\u001a\u00020\u00062\u0006\u0010a\u001a\u00020\u00062\u0006\u0010_\u001a\u00020JJF\u0010b\u001a\u00020U2\u0006\u0010Z\u001a\u00020 2\u0006\u0010V\u001a\u00020W2\u0006\u0010[\u001a\u00020\u00062\u0006\u0010\\\u001a\u00020\u00062\u0006\u0010]\u001a\u00020\u00062\u0006\u0010^\u001a\u00020\u00062\u0006\u0010c\u001a\u00020\u00062\u0006\u0010_\u001a\u00020JJ\u000e\u0010d\u001a\u00020U2\u0006\u0010V\u001a\u00020WJ\u001a\u0010e\u001a\u00020\u00062\u0006\u0010S\u001a\u00020\u00062\b\b\u0002\u0010f\u001a\u00020\u0006H\u0016J\u001a\u0010g\u001a\u00020\u00062\u0006\u0010S\u001a\u00020\u00062\b\b\u0002\u0010f\u001a\u00020\u0006H\u0016J\u0010\u0010h\u001a\u00020\u00062\u0006\u0010S\u001a\u00020\u0006H\u0016J\u0010\u0010i\u001a\u00020\u00062\u0006\u0010S\u001a\u00020\u0006H\u0016J\u0012\u0010j\u001a\u0004\u0018\u00010k2\u0006\u0010l\u001a\u00020kH\u0016J\u001a\u0010m\u001a\u00020U2\u0006\u0010n\u001a\u00020o2\b\u0010p\u001a\u0004\u0018\u00010qH\u0016JJ\u0010r\u001a\u00020U2\u0006\u0010S\u001a\u00020\u000628\u0010s\u001a4\u0012\u0013\u0012\u00110k¢\u0006\f\bu\u0012\b\bv\u0012\u0004\b\b(l\u0012\u0015\u0012\u0013\u0018\u00010k¢\u0006\f\bu\u0012\b\bv\u0012\u0004\b\b(w\u0012\u0004\u0012\u00020U0tH\u0016J\u001c\u0010x\u001a\u0004\u0018\u00010 2\b\u0010y\u001a\u0004\u0018\u00010 2\u0006\u0010z\u001a\u00020\u0006H\u0016J\n\u0010{\u001a\u0004\u0018\u00010|H\u0016R\u0011\u0010\u0005\u001a\u00020\u00068F¢\u0006\u0006\u001a\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\b\"\u0004\b\u000b\u0010\fR\u001a\u0010\r\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\b\"\u0004\b\u000f\u0010\fR\u001a\u0010\u0010\u001a\u00020\u0011X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0012\u0010\u0013\"\u0004\b\u0014\u0010\u0015R$\u0010\u0017\u001a\u00020\u00062\u0006\u0010\u0016\u001a\u00020\u0006@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0018\u0010\b\"\u0004\b\u0019\u0010\fR\u001a\u0010\u001a\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001b\u0010\b\"\u0004\b\u001c\u0010\fR\u001a\u0010\u001d\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001e\u0010\b\"\u0004\b\u001f\u0010\fR(\u0010!\u001a\u0004\u0018\u00010 2\b\u0010\u0016\u001a\u0004\u0018\u00010 @FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\"\u0010#\"\u0004\b$\u0010%R\u001a\u0010&\u001a\u00020\u0011X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b'\u0010\u0013\"\u0004\b(\u0010\u0015R\u001a\u0010)\u001a\u00020\u0011X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b*\u0010\u0013\"\u0004\b+\u0010\u0015R\u001a\u0010,\u001a\u00020\u0011X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b-\u0010\u0013\"\u0004\b.\u0010\u0015R\u001a\u0010/\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b0\u0010\b\"\u0004\b1\u0010\fR\u001a\u00102\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b3\u0010\b\"\u0004\b4\u0010\fR\u001a\u00105\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b6\u0010\b\"\u0004\b7\u0010\fR\u001a\u00108\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b9\u0010\b\"\u0004\b:\u0010\fR\u001a\u0010;\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b<\u0010\b\"\u0004\b=\u0010\fR\u001a\u0010>\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b?\u0010\b\"\u0004\b@\u0010\fR\u001a\u0010A\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bB\u0010\b\"\u0004\bC\u0010\fR\u001a\u0010D\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bE\u0010\b\"\u0004\bF\u0010\fR\u001a\u0010G\u001a\u00020\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bH\u0010\b\"\u0004\bI\u0010\fR$\u0010K\u001a\u00020J2\u0006\u0010\u0016\u001a\u00020J@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bL\u0010M\"\u0004\bN\u0010OR\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\bP\u0010Q¨\u0006~"}, m5311d2 = {"Lcom/angcyo/tablayout/DslTabIndicator;", "Lcom/angcyo/tablayout/DslGradientDrawable;", "tabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "(Lcom/angcyo/tablayout/DslTabLayout;)V", "_indicatorDrawStyle", "", "get_indicatorDrawStyle", "()I", "_targetIndex", "get_targetIndex", "set_targetIndex", "(I)V", "currentIndex", "getCurrentIndex", "setCurrentIndex", "indicatorAnim", "", "getIndicatorAnim", "()Z", "setIndicatorAnim", "(Z)V", "value", "indicatorColor", "getIndicatorColor", "setIndicatorColor", "indicatorContentId", "getIndicatorContentId", "setIndicatorContentId", "indicatorContentIndex", "getIndicatorContentIndex", "setIndicatorContentIndex", "Landroid/graphics/drawable/Drawable;", "indicatorDrawable", "getIndicatorDrawable", "()Landroid/graphics/drawable/Drawable;", "setIndicatorDrawable", "(Landroid/graphics/drawable/Drawable;)V", "indicatorEnableFlash", "getIndicatorEnableFlash", "setIndicatorEnableFlash", "indicatorEnableFlashClip", "getIndicatorEnableFlashClip", "setIndicatorEnableFlashClip", "indicatorEnableFlow", "getIndicatorEnableFlow", "setIndicatorEnableFlow", "indicatorFlowStep", "getIndicatorFlowStep", "setIndicatorFlowStep", "indicatorGravity", "getIndicatorGravity", "setIndicatorGravity", "indicatorHeight", "getIndicatorHeight", "setIndicatorHeight", "indicatorHeightOffset", "getIndicatorHeightOffset", "setIndicatorHeightOffset", "indicatorStyle", "getIndicatorStyle", "setIndicatorStyle", "indicatorWidth", "getIndicatorWidth", "setIndicatorWidth", "indicatorWidthOffset", "getIndicatorWidthOffset", "setIndicatorWidthOffset", "indicatorXOffset", "getIndicatorXOffset", "setIndicatorXOffset", "indicatorYOffset", "getIndicatorYOffset", "setIndicatorYOffset", "", "positionOffset", "getPositionOffset", "()F", "setPositionOffset", "(F)V", "getTabLayout", "()Lcom/angcyo/tablayout/DslTabLayout;", "_childConvexHeight", "index", "draw", "", "canvas", "Landroid/graphics/Canvas;", "drawHorizontal", "drawIndicator", PostHomeFragment.KEY_INDICATOR, "l", "t", "r", "b", IjkMediaPlayer.OnNativeInvokeListener.ARG_OFFSET, "drawIndicatorClipHorizontal", "endWidth", "drawIndicatorClipVertical", "endHeight", "drawVertical", "getChildTargetX", "gravity", "getChildTargetY", "getIndicatorDrawHeight", "getIndicatorDrawWidth", "indicatorContentView", "Landroid/view/View;", "childView", "initAttribute", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "targetChildView", "onChildView", "Lkotlin/Function2;", "Lkotlin/ParameterName;", "name", "contentChildView", "tintDrawableColor", "drawable", "color", "updateOriginDrawable", "Landroid/graphics/drawable/GradientDrawable;", "Companion", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.p, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslTabIndicator extends DslGradientDrawable {

    /* renamed from: q */
    public static final /* synthetic */ int f1621q = 0;

    /* renamed from: A */
    public int f1622A;

    /* renamed from: B */
    public int f1623B;

    /* renamed from: C */
    public int f1624C;

    /* renamed from: D */
    public int f1625D;

    /* renamed from: E */
    public int f1626E;

    /* renamed from: F */
    public int f1627F;

    /* renamed from: G */
    public int f1628G;

    /* renamed from: H */
    public int f1629H;

    /* renamed from: I */
    public boolean f1630I;

    /* renamed from: J */
    public float f1631J;

    /* renamed from: K */
    public int f1632K;

    /* renamed from: L */
    public int f1633L;

    /* renamed from: r */
    @NotNull
    public final DslTabLayout f1634r;

    /* renamed from: s */
    public int f1635s;

    /* renamed from: t */
    public int f1636t;

    /* renamed from: u */
    public boolean f1637u;

    /* renamed from: v */
    public boolean f1638v;

    /* renamed from: w */
    public boolean f1639w;

    /* renamed from: x */
    public int f1640x;

    /* renamed from: y */
    @Nullable
    public Drawable f1641y;

    /* renamed from: z */
    public int f1642z;

    @Metadata(m5310d1 = {"\u0000\u0010\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\n¢\u0006\u0002\b\u0005"}, m5311d2 = {"<anonymous>", "", "childView", "Landroid/view/View;", "contentChildView", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.p$a */
    public static final class a extends Lambda implements Function2<View, View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ Ref.IntRef f1643c;

        /* renamed from: e */
        public final /* synthetic */ int f1644e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(Ref.IntRef intRef, int i2) {
            super(2);
            this.f1643c = intRef;
            this.f1644e = i2;
        }

        @Override // kotlin.jvm.functions.Function2
        public Unit invoke(View view, View view2) {
            int left;
            int left2;
            int i2;
            View childView = view;
            View view3 = view2;
            Intrinsics.checkNotNullParameter(childView, "childView");
            Ref.IntRef intRef = this.f1643c;
            if (view3 == null) {
                int i3 = this.f1644e;
                if (i3 == 1) {
                    i2 = childView.getLeft();
                } else if (i3 != 2) {
                    i2 = (C4195m.m4819m0(childView) / 2) + childView.getPaddingLeft() + childView.getLeft();
                } else {
                    i2 = childView.getRight();
                }
            } else {
                int i4 = this.f1644e;
                if (i4 == 1) {
                    left = childView.getLeft();
                    left2 = view3.getLeft();
                } else if (i4 != 2) {
                    left = view3.getPaddingLeft() + view3.getLeft() + childView.getLeft();
                    left2 = C4195m.m4819m0(view3) / 2;
                } else {
                    left = childView.getLeft();
                    left2 = view3.getRight();
                }
                i2 = left + left2;
            }
            intRef.element = i2;
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0010\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003H\n¢\u0006\u0002\b\u0005"}, m5311d2 = {"<anonymous>", "", "childView", "Landroid/view/View;", "contentChildView", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.p$b */
    public static final class b extends Lambda implements Function2<View, View, Unit> {

        /* renamed from: c */
        public final /* synthetic */ Ref.IntRef f1645c;

        /* renamed from: e */
        public final /* synthetic */ int f1646e;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public b(Ref.IntRef intRef, int i2) {
            super(2);
            this.f1645c = intRef;
            this.f1646e = i2;
        }

        @Override // kotlin.jvm.functions.Function2
        public Unit invoke(View view, View view2) {
            int top;
            int top2;
            int i2;
            View childView = view;
            View view3 = view2;
            Intrinsics.checkNotNullParameter(childView, "childView");
            Ref.IntRef intRef = this.f1645c;
            if (view3 == null) {
                int i3 = this.f1646e;
                if (i3 == 1) {
                    i2 = childView.getTop();
                } else if (i3 != 2) {
                    i2 = (C4195m.m4817l0(childView) / 2) + childView.getPaddingTop() + childView.getTop();
                } else {
                    i2 = childView.getBottom();
                }
            } else {
                int i4 = this.f1646e;
                if (i4 == 1) {
                    top = childView.getTop();
                    top2 = view3.getTop();
                } else if (i4 != 2) {
                    top = view3.getPaddingTop() + view3.getTop() + childView.getTop();
                    top2 = C4195m.m4817l0(view3) / 2;
                } else {
                    top2 = childView.getTop();
                    top = childView.getBottom();
                }
                i2 = top + top2;
            }
            intRef.element = i2;
            return Unit.INSTANCE;
        }
    }

    public DslTabIndicator(@NotNull DslTabLayout tabLayout) {
        Intrinsics.checkNotNullParameter(tabLayout, "tabLayout");
        this.f1634r = tabLayout;
        this.f1636t = 4;
        this.f1639w = true;
        this.f1640x = 1;
        this.f1642z = -2;
        this.f1628G = -1;
        this.f1629H = -1;
        this.f1630I = true;
        setCallback(tabLayout);
        this.f1632K = -1;
        this.f1633L = -1;
    }

    @Override // com.angcyo.tablayout.DslGradientDrawable, android.graphics.drawable.Drawable
    public void draw(@NotNull Canvas canvas) {
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        boolean z;
        int i8;
        Drawable drawable;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        int i16;
        int i17;
        int i18;
        int i19;
        int i20;
        int i21;
        Drawable drawable2;
        int i22;
        int i23;
        int i24;
        int i25;
        int i26;
        int i27;
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        if (!isVisible() || (this.f1635s & (-4097)) == 0 || this.f1641y == null) {
            return;
        }
        if (this.f1634r.m3866d()) {
            Intrinsics.checkNotNullParameter(canvas, "canvas");
            int size = this.f1634r.getDslSelector().f1581c.size();
            int i28 = this.f1632K;
            int i29 = this.f1633L;
            if (i29 >= 0 && i29 < size) {
                i28 = Math.max(0, i28);
            }
            if (i28 >= 0 && i28 < size) {
                int m675p = m675p(i28, 4);
                int m678s = m678s(i28);
                int m677r = m677r(i28);
                int i30 = (m675p - (m678s / 2)) + this.f1626E;
                int m675p2 = m675p(this.f1633L, 4);
                int m678s2 = m678s(this.f1633L);
                int i31 = this.f1626E + (m675p2 - (m678s2 / 2));
                int i32 = this.f1633L;
                if (!(i32 >= 0 && i32 < size) || i32 == i28) {
                    i16 = i28;
                    i17 = size;
                    i18 = m678s;
                    i19 = i30;
                    i20 = m678s2;
                    i21 = 0;
                } else {
                    int m677r2 = m677r(i32);
                    if (this.f1638v) {
                        float f2 = this.f1631J;
                        i23 = (int) ((1 - f2) * m678s);
                        i24 = (int) (m678s2 * f2);
                        int i33 = (m675p - (i23 / 2)) + this.f1626E;
                        i17 = size;
                        i16 = i28;
                        i22 = i33;
                    } else if (!this.f1637u || Math.abs(this.f1633L - i28) > this.f1640x) {
                        i17 = size;
                        i16 = i28;
                        i22 = this.f1633L > i16 ? (int) (((i31 - i30) * this.f1631J) + i30) : (int) (i30 - ((i30 - i31) * this.f1631J));
                        i23 = (int) (((m678s2 - m678s) * this.f1631J) + m678s);
                        i24 = m678s2;
                    } else {
                        if (this.f1633L > i28) {
                            int i34 = i31 - i30;
                            int i35 = i34 + m678s2;
                            double d2 = this.f1631J;
                            if (d2 >= 0.5d) {
                                i17 = size;
                                i25 = i28;
                                i27 = (int) ((((d2 - 0.5d) * i34) / 0.5f) + i30);
                            } else {
                                i25 = i28;
                                i17 = size;
                                i27 = i30;
                            }
                            i26 = i35;
                        } else {
                            i25 = i28;
                            i17 = size;
                            int i36 = i30 - i31;
                            i26 = i36 + m678s;
                            float f3 = this.f1631J;
                            i27 = ((double) f3) >= 0.5d ? i31 : (int) (i30 - ((i36 * f3) / 0.5f));
                        }
                        float f4 = this.f1631J;
                        double d3 = f4;
                        i23 = d3 >= 0.5d ? (int) (i26 - (((d3 - 0.5d) * (i26 - m678s2)) / 0.5f)) : (int) ((((i26 - m678s) * f4) / 0.5f) + m678s);
                        i22 = i27;
                        i24 = m678s2;
                        i16 = i25;
                    }
                    i18 = i23;
                    i20 = i24;
                    i21 = (int) ((m677r2 - m677r) * this.f1631J);
                    i19 = i22;
                }
                int i37 = this.f1635s & (-4097);
                int f8751i = i37 != 1 ? i37 != 2 ? ((this.f1634r.getF8751I() - m671l(i16)) / 2) + (((((((m650g() - m648e()) - m645b()) / 2) + m648e()) - (m677r / 2)) + this.f1627F) - i21) : (m650g() - m677r) - this.f1627F : this.f1627F + 0;
                Drawable drawable3 = this.f1641y;
                if (drawable3 == null) {
                    return;
                }
                if (!this.f1638v) {
                    m672m(drawable3, canvas, i19, f8751i, i19 + i18, m677r + f8751i + i21, 1 - this.f1631J);
                    return;
                }
                if (this.f1639w) {
                    drawable2 = drawable3;
                    m673n(drawable3, canvas, i30, f8751i, i30 + m678s, f8751i + m677r + i21, i18, 1 - this.f1631J);
                } else {
                    drawable2 = drawable3;
                    m672m(drawable2, canvas, i19, f8751i, i19 + i18, f8751i + m677r + i21, 1 - this.f1631J);
                }
                int i38 = this.f1633L;
                if (i38 >= 0 && i38 < i17) {
                    if (this.f1639w) {
                        m673n(drawable2, canvas, i31, f8751i, i31 + m678s2, m677r + f8751i + i21, i20, this.f1631J);
                        return;
                    } else {
                        m672m(drawable2, canvas, i31, f8751i, i31 + i20, m677r + f8751i + i21, this.f1631J);
                        return;
                    }
                }
                return;
            }
            return;
        }
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        int size2 = this.f1634r.getDslSelector().f1581c.size();
        int i39 = this.f1632K;
        int i40 = this.f1633L;
        if (i40 >= 0 && i40 < size2) {
            i39 = Math.max(0, i39);
        }
        if (i39 >= 0 && i39 < size2) {
            int m676q = m676q(i39, 4);
            int m678s3 = m678s(i39);
            int m677r3 = m677r(i39);
            int i41 = this.f1627F + (m676q - (m677r3 / 2));
            int m676q2 = m676q(this.f1633L, 4);
            int m677r4 = m677r(this.f1633L);
            int i42 = (m676q2 - (m677r4 / 2)) + this.f1627F;
            int i43 = this.f1633L;
            if (!(i43 >= 0 && i43 < size2) || i43 == i39) {
                i2 = size2;
                i3 = m677r3;
                i4 = i41;
                i5 = m677r4;
                i6 = i42;
                i7 = 0;
            } else {
                int m678s4 = m678s(i43);
                if (this.f1638v) {
                    float f5 = this.f1631J;
                    i12 = (int) ((1 - f5) * m677r3);
                    i13 = (int) (m677r4 * f5);
                    int i44 = this.f1626E;
                    i10 = (m676q - (i12 / 2)) + i44;
                    i14 = (m676q2 - (i13 / 2)) + i44;
                    i9 = m678s4;
                    i2 = size2;
                } else {
                    if (!this.f1637u || Math.abs(this.f1633L - i39) > this.f1640x) {
                        i9 = m678s4;
                        i2 = size2;
                        i10 = this.f1633L > i39 ? (int) (((i42 - i41) * this.f1631J) + i41) : (int) (i41 - ((i41 - i42) * this.f1631J));
                        i11 = (int) (((m677r4 - m677r3) * this.f1631J) + m677r3);
                    } else {
                        if (this.f1633L > i39) {
                            int i45 = i42 - i41;
                            i15 = i45 + m677r4;
                            double d4 = this.f1631J;
                            if (d4 >= 0.5d) {
                                i2 = size2;
                                i9 = m678s4;
                                i10 = (int) ((((d4 - 0.5d) * i45) / 0.5f) + i41);
                                i15 = i15;
                            } else {
                                i9 = m678s4;
                                i2 = size2;
                                i10 = i41;
                            }
                        } else {
                            i9 = m678s4;
                            i2 = size2;
                            int i46 = i41 - i42;
                            i15 = i46 + m677r3;
                            float f6 = this.f1631J;
                            i10 = ((double) f6) >= 0.5d ? i42 : (int) (i41 - ((i46 * f6) / 0.5f));
                        }
                        float f7 = this.f1631J;
                        double d5 = f7;
                        i11 = d5 >= 0.5d ? (int) (i15 - (((d5 - 0.5d) * (i15 - m677r4)) / 0.5f)) : (int) ((((i15 - m677r3) * f7) / 0.5f) + m677r3);
                    }
                    i12 = i11;
                    i13 = m677r4;
                    i14 = i42;
                }
                i6 = i14;
                i7 = (int) ((i9 - m678s3) * this.f1631J);
                i5 = i13;
                i4 = i10;
                i3 = i12;
            }
            int i47 = this.f1635s & (-4097);
            if (i47 != 1) {
                i8 = i47 != 2 ? (((((m651h() - m646c()) - m647d()) / 2) - (m678s3 / 2)) + (m646c() + this.f1626E)) - ((this.f1634r.getF8751I() - m671l(i39)) / 2) : (m651h() - m678s3) - this.f1626E;
                z = false;
            } else {
                z = false;
                i8 = this.f1626E + 0;
            }
            Drawable drawable4 = this.f1641y;
            if (drawable4 == null) {
                return;
            }
            if (!this.f1638v) {
                m672m(drawable4, canvas, i8, i4, i8 + m678s3 + i7, i3 + i4, 1 - this.f1631J);
                return;
            }
            if (this.f1639w) {
                drawable = drawable4;
                m674o(drawable4, canvas, i8, i41, i8 + m678s3 + i7, i41 + m677r3, i3, 1 - this.f1631J);
            } else {
                drawable = drawable4;
                m672m(drawable, canvas, i8, i4, i8 + m678s3 + i7, i3 + i4, 1 - this.f1631J);
            }
            int i48 = this.f1633L;
            if (i48 >= 0 && i48 < i2) {
                z = true;
            }
            if (z) {
                if (this.f1639w) {
                    m674o(drawable, canvas, i8, i42, i8 + m678s3 + i7, i42 + m677r4, i5, this.f1631J);
                } else {
                    m672m(drawable, canvas, i8, i6, i8 + m678s3 + i7, i6 + i5, this.f1631J);
                }
            }
        }
    }

    @Override // com.angcyo.tablayout.DslGradientDrawable
    @Nullable
    /* renamed from: k */
    public GradientDrawable mo657k() {
        GradientDrawable mo657k = super.mo657k();
        m681v(this.f1565n);
        return mo657k;
    }

    /* renamed from: l */
    public final int m671l(int i2) {
        if (!(m644a() instanceof ViewGroup)) {
            return 0;
        }
        View m644a = m644a();
        Objects.requireNonNull(m644a, "null cannot be cast to non-null type android.view.ViewGroup");
        ViewGroup.LayoutParams layoutParams = ((ViewGroup) m644a).getChildAt(i2).getLayoutParams();
        DslTabLayout.C3200a c3200a = layoutParams instanceof DslTabLayout.C3200a ? (DslTabLayout.C3200a) layoutParams : null;
        if (c3200a == null) {
            return 0;
        }
        return c3200a.f8783c;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: m */
    public final void m672m(@NotNull Drawable indicator, @NotNull Canvas canvas, int i2, int i3, int i4, int i5, float f2) {
        Intrinsics.checkNotNullParameter(indicator, "indicator");
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        indicator.setBounds(i2, i3, i4, i5);
        if (indicator instanceof ITabIndicatorDraw) {
            ((ITabIndicatorDraw) indicator).m686a(this, canvas, f2);
        } else {
            indicator.draw(canvas);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: n */
    public final void m673n(@NotNull Drawable indicator, @NotNull Canvas canvas, int i2, int i3, int i4, int i5, int i6, float f2) {
        Intrinsics.checkNotNullParameter(indicator, "indicator");
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        canvas.save();
        int i7 = ((i4 - i2) - i6) / 2;
        canvas.clipRect(i2 + i7, i3, i4 - i7, i5);
        indicator.setBounds(i2, i3, i4, i5);
        if (indicator instanceof ITabIndicatorDraw) {
            ((ITabIndicatorDraw) indicator).m686a(this, canvas, f2);
        } else {
            indicator.draw(canvas);
        }
        canvas.restore();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: o */
    public final void m674o(@NotNull Drawable indicator, @NotNull Canvas canvas, int i2, int i3, int i4, int i5, int i6, float f2) {
        Intrinsics.checkNotNullParameter(indicator, "indicator");
        Intrinsics.checkNotNullParameter(canvas, "canvas");
        canvas.save();
        int i7 = ((i5 - i3) - i6) / 2;
        canvas.clipRect(i2, i3 + i7, i4, i5 - i7);
        indicator.setBounds(i2, i3, i4, i5);
        if (indicator instanceof ITabIndicatorDraw) {
            ((ITabIndicatorDraw) indicator).m686a(this, canvas, f2);
        } else {
            indicator.draw(canvas);
        }
        canvas.restore();
    }

    /* renamed from: p */
    public int m675p(int i2, int i3) {
        Ref.IntRef intRef = new Ref.IntRef();
        intRef.element = i2 > 0 ? this.f1634r.getMaxWidth() : 0;
        m682w(i2, new a(intRef, i3));
        return intRef.element;
    }

    /* renamed from: q */
    public int m676q(int i2, int i3) {
        Ref.IntRef intRef = new Ref.IntRef();
        intRef.element = i2 > 0 ? this.f1634r.getMaxHeight() : 0;
        m682w(i2, new b(intRef, i3));
        return intRef.element;
    }

    /* renamed from: r */
    public int m677r(int i2) {
        View view;
        int i3 = this.f1624C;
        if (i3 == -2) {
            View view2 = (View) CollectionsKt___CollectionsKt.getOrNull(this.f1634r.getDslSelector().f1581c, i2);
            if (view2 != null) {
                View m679t = m679t(view2);
                Integer valueOf = m679t == null ? null : Integer.valueOf(C4195m.m4817l0(m679t));
                i3 = valueOf == null ? C4195m.m4817l0(view2) : valueOf.intValue();
            }
        } else if (i3 == -1 && (view = (View) CollectionsKt___CollectionsKt.getOrNull(this.f1634r.getDslSelector().f1581c, i2)) != null) {
            i3 = view.getMeasuredHeight();
        }
        return i3 + this.f1625D;
    }

    /* renamed from: s */
    public int m678s(int i2) {
        View view;
        int i3 = this.f1622A;
        if (i3 == -2) {
            View view2 = (View) CollectionsKt___CollectionsKt.getOrNull(this.f1634r.getDslSelector().f1581c, i2);
            if (view2 != null) {
                View m679t = m679t(view2);
                Integer valueOf = m679t == null ? null : Integer.valueOf(C4195m.m4819m0(m679t));
                i3 = valueOf == null ? C4195m.m4819m0(view2) : valueOf.intValue();
            }
        } else if (i3 == -1 && (view = (View) CollectionsKt___CollectionsKt.getOrNull(this.f1634r.getDslSelector().f1581c, i2)) != null) {
            i3 = view.getMeasuredWidth();
        }
        return i3 + this.f1623B;
    }

    @Nullable
    /* renamed from: t */
    public View m679t(@NotNull View childView) {
        Intrinsics.checkNotNullParameter(childView, "childView");
        ViewGroup.LayoutParams layoutParams = childView.getLayoutParams();
        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type com.angcyo.tablayout.DslTabLayout.LayoutParams");
        DslTabLayout.C3200a c3200a = (DslTabLayout.C3200a) layoutParams;
        int i2 = c3200a.f8785e;
        if (i2 == -1) {
            i2 = this.f1629H;
        }
        if (i2 != -1) {
            return childView.findViewById(i2);
        }
        int i3 = c3200a.f8784d;
        if (i3 < 0) {
            i3 = this.f1628G;
        }
        if (i3 >= 0 && (childView instanceof ViewGroup)) {
            boolean z = false;
            if (i3 >= 0 && i3 < ((ViewGroup) childView).getChildCount()) {
                z = true;
            }
            if (z) {
                return ((ViewGroup) childView).getChildAt(i3);
            }
        }
        return null;
    }

    /* renamed from: u */
    public void m680u(@NotNull Context context, @Nullable AttributeSet attributeSet) {
        int[] iArr;
        Intrinsics.checkNotNullParameter(context, "context");
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, R$styleable.DslTabLayout);
        Intrinsics.checkNotNullExpressionValue(obtainStyledAttributes, "context.obtainStyledAttr…R.styleable.DslTabLayout)");
        m681v(obtainStyledAttributes.getDrawable(R$styleable.DslTabLayout_tab_indicator_drawable));
        this.f1642z = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_indicator_color, this.f1642z);
        m681v(this.f1641y);
        boolean z = true;
        this.f1635s = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_indicator_style, this.f1634r.m3866d() ? 2 : 1);
        this.f1636t = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_indicator_gravity, this.f1636t);
        if (C4195m.m4823o0(this.f1635s, 9)) {
            if (this.f1634r.m3866d()) {
                this.f1622A = -1;
                this.f1624C = -1;
            } else {
                this.f1624C = -1;
                this.f1622A = -1;
            }
            this.f1622A = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_indicator_width, this.f1622A);
            this.f1624C = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_indicator_height, this.f1624C);
            this.f1626E = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_x_offset, this.f1626E);
            this.f1627F = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_y_offset, this.f1627F);
        } else {
            this.f1622A = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_indicator_width, this.f1634r.m3866d() ? -1 : C4195m.m4801d0() * 3);
            this.f1624C = obtainStyledAttributes.getLayoutDimension(R$styleable.DslTabLayout_tab_indicator_height, this.f1634r.m3866d() ? C4195m.m4801d0() * 3 : -1);
            this.f1626E = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_x_offset, this.f1634r.m3866d() ? 0 : C4195m.m4801d0() * 2);
            this.f1627F = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_y_offset, this.f1634r.m3866d() ? C4195m.m4801d0() * 2 : 0);
        }
        this.f1640x = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_indicator_flow_step, this.f1640x);
        this.f1637u = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_indicator_enable_flow, this.f1637u);
        this.f1638v = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_indicator_enable_flash, this.f1638v);
        this.f1639w = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_indicator_enable_flash_clip, this.f1639w);
        this.f1623B = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_width_offset, this.f1623B);
        this.f1625D = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_height_offset, this.f1625D);
        this.f1628G = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_indicator_content_index, this.f1628G);
        this.f1629H = obtainStyledAttributes.getResourceId(R$styleable.DslTabLayout_tab_indicator_content_id, this.f1629H);
        this.f1630I = obtainStyledAttributes.getBoolean(R$styleable.DslTabLayout_tab_indicator_anim, this.f1630I);
        this.f1553b = obtainStyledAttributes.getInt(R$styleable.DslTabLayout_tab_indicator_shape, this.f1553b);
        this.f1554c = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_indicator_solid_color, this.f1554c);
        this.f1555d = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_indicator_stroke_color, this.f1555d);
        this.f1556e = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_stroke_width, this.f1556e);
        this.f1557f = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_dash_width, (int) this.f1557f);
        this.f1558g = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_dash_gap, (int) this.f1558g);
        int dimensionPixelOffset = obtainStyledAttributes.getDimensionPixelOffset(R$styleable.DslTabLayout_tab_indicator_radius, 0);
        if (dimensionPixelOffset > 0) {
            Arrays.fill(this.f1559h, dimensionPixelOffset);
        } else {
            String string = obtainStyledAttributes.getString(R$styleable.DslTabLayout_tab_indicator_radii);
            if (string != null) {
                float[] array = this.f1559h;
                Intrinsics.checkNotNullParameter(array, "array");
                if (!(string.length() == 0)) {
                    List split$default = StringsKt__StringsKt.split$default((CharSequence) string, new String[]{ChineseToPinyinResource.Field.COMMA}, false, 0, 6, (Object) null);
                    if (split$default.size() != 8) {
                        throw new IllegalArgumentException("radii 需要8个值.");
                    }
                    float f2 = Resources.getSystem().getDisplayMetrics().density;
                    int size = split$default.size();
                    for (int i2 = 0; i2 < size; i2++) {
                        array[i2] = Float.parseFloat((String) split$default.get(i2)) * f2;
                    }
                }
            }
        }
        String string2 = obtainStyledAttributes.getString(R$styleable.DslTabLayout_tab_indicator_gradient_colors);
        if (string2 == null || string2.length() == 0) {
            int color = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_indicator_gradient_start_color, 0);
            int color2 = obtainStyledAttributes.getColor(R$styleable.DslTabLayout_tab_indicator_gradient_end_color, 0);
            iArr = color != color2 ? new int[]{color, color2} : this.f1560i;
        } else {
            if (string2 != null && string2.length() != 0) {
                z = false;
            }
            if (z) {
                iArr = null;
            } else {
                List split$default2 = StringsKt__StringsKt.split$default((CharSequence) string2, new String[]{ChineseToPinyinResource.Field.COMMA}, false, 0, 6, (Object) null);
                int size2 = split$default2.size();
                int[] iArr2 = new int[size2];
                for (int i3 = 0; i3 < size2; i3++) {
                    String str = (String) split$default2.get(i3);
                    iArr2[i3] = StringsKt__StringsJVMKt.startsWith$default(str, "#", false, 2, null) ? Color.parseColor(str) : Integer.parseInt(str);
                }
                iArr = iArr2;
            }
            if (iArr == null) {
                iArr = this.f1560i;
            }
        }
        this.f1560i = iArr;
        obtainStyledAttributes.recycle();
        if (this.f1641y == null && m655i()) {
            mo657k();
        }
    }

    /* renamed from: v */
    public final void m681v(@Nullable Drawable drawable) {
        int i2 = this.f1642z;
        if (drawable != null && i2 != -2) {
            drawable = C4195m.m4778L0(drawable, i2);
        }
        this.f1641y = drawable;
    }

    /* renamed from: w */
    public void m682w(int i2, @NotNull Function2<? super View, ? super View, Unit> onChildView) {
        Intrinsics.checkNotNullParameter(onChildView, "onChildView");
        View view = (View) CollectionsKt___CollectionsKt.getOrNull(this.f1634r.getDslSelector().f1581c, i2);
        if (view == null) {
            return;
        }
        onChildView.invoke(view, m679t(view));
    }
}
