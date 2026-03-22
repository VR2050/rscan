package com.angcyo.tablayout;

import android.graphics.Color;
import android.text.TextPaint;
import android.view.KeyEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.IdRes;
import androidx.core.view.ViewCompat;
import com.angcyo.tablayout.DslTabLayout;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000d\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u000b\n\u0002\b\u001b\n\u0002\u0018\u0002\n\u0002\b$\n\u0002\u0010\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0016\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003¢\u0006\u0002\u0010\u0004J*\u0010e\u001a\u00020f2\b\u0010g\u001a\u0004\u0018\u00010\u00142\u0006\u0010h\u001a\u00020\u00072\u0006\u0010i\u001a\u00020\u00072\u0006\u0010j\u001a\u00020\fH\u0016J*\u0010k\u001a\u00020f2\b\u0010g\u001a\u0004\u0018\u00010\u00142\u0006\u0010h\u001a\u00020\u00072\u0006\u0010i\u001a\u00020\u00072\u0006\u0010j\u001a\u00020\fH\u0016J*\u0010l\u001a\u00020f2\b\u0010g\u001a\u0004\u0018\u00010\u00142\u0006\u0010m\u001a\u00020\f2\u0006\u0010n\u001a\u00020\f2\u0006\u0010j\u001a\u00020\fH\u0016J*\u0010o\u001a\u00020f2\b\u0010g\u001a\u0004\u0018\u00010\u001c2\u0006\u0010p\u001a\u00020\f2\u0006\u0010q\u001a\u00020\f2\u0006\u0010j\u001a\u00020\fH\u0016J\u001a\u0010r\u001a\u00020f2\b\u0010g\u001a\u0004\u0018\u00010\u00142\u0006\u0010s\u001a\u00020\u0007H\u0016J\u001c\u0010t\u001a\u00020f2\u0006\u0010u\u001a\u00020v2\n\b\u0002\u0010w\u001a\u0004\u0018\u00010xH\u0016J \u0010y\u001a\u00020f2\u0006\u0010\n\u001a\u00020\u00072\u0006\u0010\u000b\u001a\u00020\u00072\u0006\u0010\r\u001a\u00020\fH\u0016J\"\u0010z\u001a\u00020f2\b\u0010{\u001a\u0004\u0018\u00010\u00142\u0006\u0010|\u001a\u00020\u00142\u0006\u0010\r\u001a\u00020\fH\u0016J \u0010}\u001a\u00020f2\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u00072\u0006\u0010~\u001a\u00020%H\u0016R_\u0010\u0005\u001aG\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\n\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u000b\u0012\u0013\u0012\u00110\f¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\r\u0012\u0004\u0012\u00020\u00070\u0006X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011RL\u0010\u0012\u001a4\u0012\u0013\u0012\u00110\u0014¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u0015\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u0016\u0012\u0006\u0012\u0004\u0018\u00010\u00140\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0017\u0010\u0018\"\u0004\b\u0019\u0010\u001aRL\u0010\u001b\u001a4\u0012\u0013\u0012\u00110\u0014¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u0015\u0012\u0013\u0012\u00110\u0007¢\u0006\f\b\b\u0012\b\b\t\u0012\u0004\b\b(\u0016\u0012\u0006\u0012\u0004\u0018\u00010\u001c0\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001d\u0010\u0018\"\u0004\b\u001e\u0010\u001aR\u001a\u0010\u001f\u001a\u00020\u0007X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b \u0010!\"\u0004\b\"\u0010#R$\u0010&\u001a\u00020%2\u0006\u0010$\u001a\u00020%@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b'\u0010(\"\u0004\b)\u0010*R\u001a\u0010+\u001a\u00020%X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b,\u0010(\"\u0004\b-\u0010*R\u001a\u0010.\u001a\u00020%X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b/\u0010(\"\u0004\b0\u0010*R\u001a\u00101\u001a\u00020%X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b2\u0010(\"\u0004\b3\u0010*R\u001a\u00104\u001a\u00020%X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b5\u0010(\"\u0004\b6\u0010*R\u001a\u00107\u001a\u00020%X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b8\u0010(\"\u0004\b9\u0010*R\u001a\u0010:\u001a\u00020%X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b;\u0010(\"\u0004\b<\u0010*R$\u0010=\u001a\u00020%2\u0006\u0010$\u001a\u00020%@FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b>\u0010(\"\u0004\b?\u0010*R\u001a\u0010@\u001a\u00020AX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bB\u0010C\"\u0004\bD\u0010ER\u001c\u0010F\u001a\u00020\u00078FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bG\u0010!\"\u0004\bH\u0010#R\u001c\u0010I\u001a\u00020\u00078FX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bJ\u0010!\"\u0004\bK\u0010#R\u001e\u0010L\u001a\u00020\u00078\u0006@\u0006X\u0087\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bM\u0010!\"\u0004\bN\u0010#R\u0011\u0010\u0002\u001a\u00020\u0003¢\u0006\b\n\u0000\u001a\u0004\bO\u0010PR\u001a\u0010Q\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bR\u0010S\"\u0004\bT\u0010UR\u001a\u0010V\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bW\u0010S\"\u0004\bX\u0010UR\u001a\u0010Y\u001a\u00020\u0007X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bZ\u0010!\"\u0004\b[\u0010#R\u001a\u0010\\\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b]\u0010S\"\u0004\b^\u0010UR\u001a\u0010_\u001a\u00020\fX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b`\u0010S\"\u0004\ba\u0010UR\u001e\u0010b\u001a\u00020\u00078\u0006@\u0006X\u0087\u000e¢\u0006\u000e\n\u0000\u001a\u0004\bc\u0010!\"\u0004\bd\u0010#¨\u0006\u007f"}, m5311d2 = {"Lcom/angcyo/tablayout/DslTabLayoutConfig;", "Lcom/angcyo/tablayout/DslSelectorConfig;", "tabLayout", "Lcom/angcyo/tablayout/DslTabLayout;", "(Lcom/angcyo/tablayout/DslTabLayout;)V", "onGetGradientIndicatorColor", "Lkotlin/Function3;", "", "Lkotlin/ParameterName;", "name", "fromIndex", "toIndex", "", "positionOffset", "getOnGetGradientIndicatorColor", "()Lkotlin/jvm/functions/Function3;", "setOnGetGradientIndicatorColor", "(Lkotlin/jvm/functions/Function3;)V", "onGetIcoStyleView", "Lkotlin/Function2;", "Landroid/view/View;", "itemView", "index", "getOnGetIcoStyleView", "()Lkotlin/jvm/functions/Function2;", "setOnGetIcoStyleView", "(Lkotlin/jvm/functions/Function2;)V", "onGetTextStyleView", "Landroid/widget/TextView;", "getOnGetTextStyleView", "setOnGetTextStyleView", "tabDeselectColor", "getTabDeselectColor", "()I", "setTabDeselectColor", "(I)V", "value", "", "tabEnableGradientColor", "getTabEnableGradientColor", "()Z", "setTabEnableGradientColor", "(Z)V", "tabEnableGradientScale", "getTabEnableGradientScale", "setTabEnableGradientScale", "tabEnableGradientTextSize", "getTabEnableGradientTextSize", "setTabEnableGradientTextSize", "tabEnableIcoColor", "getTabEnableIcoColor", "setTabEnableIcoColor", "tabEnableIcoGradientColor", "getTabEnableIcoGradientColor", "setTabEnableIcoGradientColor", "tabEnableIndicatorGradientColor", "getTabEnableIndicatorGradientColor", "setTabEnableIndicatorGradientColor", "tabEnableTextBold", "getTabEnableTextBold", "setTabEnableTextBold", "tabEnableTextColor", "getTabEnableTextColor", "setTabEnableTextColor", "tabGradientCallback", "Lcom/angcyo/tablayout/TabGradientCallback;", "getTabGradientCallback", "()Lcom/angcyo/tablayout/TabGradientCallback;", "setTabGradientCallback", "(Lcom/angcyo/tablayout/TabGradientCallback;)V", "tabIcoDeselectColor", "getTabIcoDeselectColor", "setTabIcoDeselectColor", "tabIcoSelectColor", "getTabIcoSelectColor", "setTabIcoSelectColor", "tabIconViewId", "getTabIconViewId", "setTabIconViewId", "getTabLayout", "()Lcom/angcyo/tablayout/DslTabLayout;", "tabMaxScale", "getTabMaxScale", "()F", "setTabMaxScale", "(F)V", "tabMinScale", "getTabMinScale", "setTabMinScale", "tabSelectColor", "getTabSelectColor", "setTabSelectColor", "tabTextMaxSize", "getTabTextMaxSize", "setTabTextMaxSize", "tabTextMinSize", "getTabTextMinSize", "setTabTextMinSize", "tabTextViewId", "getTabTextViewId", "setTabTextViewId", "_gradientColor", "", "view", "startColor", "endColor", "percent", "_gradientIcoColor", "_gradientScale", "startScale", "endScale", "_gradientTextSize", "startTextSize", "endTextSize", "_updateIcoColor", "color", "initAttribute", "context", "Landroid/content/Context;", "attributeSet", "Landroid/util/AttributeSet;", "onPageIndexScrolled", "onPageViewScrolled", "fromView", "toView", "onUpdateItemStyle", "select", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.x, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslTabLayoutConfig extends DslSelectorConfig {

    /* renamed from: A */
    @NotNull
    public Function3<? super Integer, ? super Integer, ? super Float, Integer> f1654A;

    /* renamed from: e */
    @NotNull
    public final DslTabLayout f1655e;

    /* renamed from: f */
    public boolean f1656f;

    /* renamed from: g */
    public boolean f1657g;

    /* renamed from: h */
    public boolean f1658h;

    /* renamed from: i */
    public int f1659i;

    /* renamed from: j */
    public int f1660j;

    /* renamed from: k */
    public boolean f1661k;

    /* renamed from: l */
    public boolean f1662l;

    /* renamed from: m */
    public boolean f1663m;

    /* renamed from: n */
    public int f1664n;

    /* renamed from: o */
    public int f1665o;

    /* renamed from: p */
    public boolean f1666p;

    /* renamed from: q */
    public float f1667q;

    /* renamed from: r */
    public float f1668r;

    /* renamed from: s */
    public boolean f1669s;

    /* renamed from: t */
    public float f1670t;

    /* renamed from: u */
    public float f1671u;

    /* renamed from: v */
    @NotNull
    public TabGradientCallback f1672v;

    /* renamed from: w */
    @IdRes
    public int f1673w;

    /* renamed from: x */
    @IdRes
    public int f1674x;

    /* renamed from: y */
    @NotNull
    public Function2<? super View, ? super Integer, ? extends TextView> f1675y;

    /* renamed from: z */
    @NotNull
    public Function2<? super View, ? super Integer, ? extends View> f1676z;

    @Metadata(m5310d1 = {"\u0000\u001a\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0000\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\n¢\u0006\u0002\b\b"}, m5311d2 = {"<anonymous>", "", "itemView", "Landroid/view/View;", "index", "", "select", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.x$a */
    public static final class a extends Lambda implements Function3<View, Integer, Boolean, Unit> {
        public a() {
            super(3);
        }

        @Override // kotlin.jvm.functions.Function3
        public Unit invoke(View view, Integer num, Boolean bool) {
            DslTabBorder f8768n;
            View invoke;
            View itemView = view;
            int intValue = num.intValue();
            boolean booleanValue = bool.booleanValue();
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            DslTabLayoutConfig dslTabLayoutConfig = DslTabLayoutConfig.this;
            Objects.requireNonNull(dslTabLayoutConfig);
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            TextView invoke2 = dslTabLayoutConfig.f1675y.invoke(itemView, Integer.valueOf(intValue));
            if (invoke2 != null) {
                TextPaint paint = invoke2.getPaint();
                if (paint != null) {
                    paint.setFlags((dslTabLayoutConfig.f1661k && booleanValue) ? invoke2.getPaint().getFlags() | 32 : invoke2.getPaint().getFlags() & (-33));
                }
                if (dslTabLayoutConfig.f1656f) {
                    invoke2.setTextColor(booleanValue ? dslTabLayoutConfig.f1659i : dslTabLayoutConfig.f1660j);
                }
                float f2 = dslTabLayoutConfig.f1671u;
                if (f2 > 0.0f || dslTabLayoutConfig.f1670t > 0.0f) {
                    float min = Math.min(dslTabLayoutConfig.f1670t, f2);
                    float max = Math.max(dslTabLayoutConfig.f1670t, dslTabLayoutConfig.f1671u);
                    if (booleanValue) {
                        min = max;
                    }
                    invoke2.setTextSize(0, min);
                }
            }
            if (dslTabLayoutConfig.f1662l && (invoke = dslTabLayoutConfig.f1676z.invoke(itemView, Integer.valueOf(intValue))) != null) {
                dslTabLayoutConfig.f1672v.m641a(invoke, booleanValue ? dslTabLayoutConfig.m685c() : dslTabLayoutConfig.m684b());
            }
            if (dslTabLayoutConfig.f1666p) {
                itemView.setScaleX(booleanValue ? dslTabLayoutConfig.f1668r : dslTabLayoutConfig.f1667q);
                itemView.setScaleY(booleanValue ? dslTabLayoutConfig.f1668r : dslTabLayoutConfig.f1667q);
            }
            if (dslTabLayoutConfig.f1655e.getF8769o() && (f8768n = dslTabLayoutConfig.f1655e.getF8768n()) != null) {
                DslTabLayout tabLayout = dslTabLayoutConfig.f1655e;
                Intrinsics.checkNotNullParameter(tabLayout, "tabLayout");
                Intrinsics.checkNotNullParameter(itemView, "itemView");
                if (f8768n.f1603q) {
                    if (booleanValue) {
                        boolean z = intValue == 0;
                        boolean z2 = intValue == tabLayout.getDslSelector().f1581c.size() - 1;
                        DslGradientDrawable dslGradientDrawable = new DslGradientDrawable();
                        C1515l config = new C1515l(f8768n, z, z2, tabLayout);
                        Intrinsics.checkNotNullParameter(config, "config");
                        config.invoke(dslGradientDrawable);
                        dslGradientDrawable.mo657k();
                        f8768n.f1607u = dslGradientDrawable;
                        ViewCompat.setBackground(itemView, dslGradientDrawable);
                    } else {
                        ViewCompat.setBackground(itemView, null);
                    }
                }
            }
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u001c\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0007H\n¢\u0006\u0002\b\t"}, m5311d2 = {"<anonymous>", "", "fromIndex", "", "selectIndexList", "", "reselect", "", "fromUser", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.x$b */
    public static final class b extends Lambda implements Function4<Integer, List<? extends Integer>, Boolean, Boolean, Unit> {
        public b() {
            super(4);
        }

        @Override // kotlin.jvm.functions.Function4
        public Unit invoke(Integer num, List<? extends Integer> list, Boolean bool, Boolean bool2) {
            int intValue = num.intValue();
            List<? extends Integer> selectIndexList = list;
            boolean booleanValue = bool.booleanValue();
            boolean booleanValue2 = bool2.booleanValue();
            Intrinsics.checkNotNullParameter(selectIndexList, "selectIndexList");
            int intValue2 = ((Number) CollectionsKt___CollectionsKt.last((List) selectIndexList)).intValue();
            ViewPagerDelegate f8756n = DslTabLayoutConfig.this.f1655e.getF8756N();
            if (f8756n != null) {
                f8756n.mo642a(intValue, intValue2, booleanValue, booleanValue2);
            }
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0012\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\u0007\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u00012\u0006\u0010\u0004\u001a\u00020\u0005H\n¢\u0006\u0004\b\u0006\u0010\u0007"}, m5311d2 = {"<anonymous>", "", "fromIndex", "toIndex", "positionOffset", "", "invoke", "(IIF)Ljava/lang/Integer;"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.x$c */
    public static final class c extends Lambda implements Function3<Integer, Integer, Float, Integer> {
        public c() {
            super(3);
        }

        @Override // kotlin.jvm.functions.Function3
        public Integer invoke(Integer num, Integer num2, Float f2) {
            num.intValue();
            num2.intValue();
            f2.floatValue();
            return Integer.valueOf(DslTabLayoutConfig.this.f1655e.getF8764j().f1642z);
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0010\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\u0010\u0000\u001a\u0004\u0018\u00010\u00012\u0006\u0010\u0002\u001a\u00020\u00012\u0006\u0010\u0003\u001a\u00020\u0004H\n¢\u0006\u0002\b\u0005"}, m5311d2 = {"<anonymous>", "Landroid/view/View;", "itemView", "<anonymous parameter 1>", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.x$d */
    public static final class d extends Lambda implements Function2<View, Integer, View> {
        public d() {
            super(2);
        }

        @Override // kotlin.jvm.functions.Function2
        public View invoke(View view, Integer num) {
            View view2;
            View findViewById;
            View findViewById2;
            View itemView = view;
            num.intValue();
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            DslTabLayoutConfig dslTabLayoutConfig = DslTabLayoutConfig.this;
            int i2 = dslTabLayoutConfig.f1674x;
            if (i2 != -1) {
                return itemView.findViewById(i2);
            }
            if (dslTabLayoutConfig.f1655e.getF8764j().f1628G == -1 || (view2 = C4195m.m4795a0(itemView, DslTabLayoutConfig.this.f1655e.getF8764j().f1628G)) == null) {
                view2 = itemView;
            }
            if (DslTabLayoutConfig.this.f1655e.getF8764j().f1629H != -1 && (findViewById2 = itemView.findViewById(DslTabLayoutConfig.this.f1655e.getF8764j().f1629H)) != null) {
                view2 = findViewById2;
            }
            ViewGroup.LayoutParams layoutParams = itemView.getLayoutParams();
            if (!(layoutParams instanceof DslTabLayout.C3200a)) {
                return view2;
            }
            DslTabLayout.C3200a c3200a = (DslTabLayout.C3200a) layoutParams;
            int i3 = c3200a.f8784d;
            if (i3 != -1 && (itemView instanceof ViewGroup)) {
                view2 = C4195m.m4795a0(itemView, i3);
            }
            int i4 = c3200a.f8785e;
            return (i4 == -1 || (findViewById = itemView.findViewById(i4)) == null) ? view2 : findViewById;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0014\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\u0010\u0000\u001a\u0004\u0018\u00010\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u0005H\n¢\u0006\u0002\b\u0006"}, m5311d2 = {"<anonymous>", "Landroid/widget/TextView;", "itemView", "Landroid/view/View;", "<anonymous parameter 1>", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.x$e */
    public static final class e extends Lambda implements Function2<View, Integer, TextView> {
        public e() {
            super(2);
        }

        @Override // kotlin.jvm.functions.Function2
        public TextView invoke(View view, Integer num) {
            KeyEvent.Callback findViewById;
            KeyEvent.Callback m4795a0;
            KeyEvent.Callback findViewById2;
            KeyEvent.Callback m4795a02;
            View itemView = view;
            num.intValue();
            Intrinsics.checkNotNullParameter(itemView, "itemView");
            DslTabLayoutConfig dslTabLayoutConfig = DslTabLayoutConfig.this;
            int i2 = dslTabLayoutConfig.f1673w;
            if (i2 != -1) {
                return (TextView) itemView.findViewById(i2);
            }
            KeyEvent.Callback callback = itemView instanceof TextView ? (TextView) itemView : null;
            if (dslTabLayoutConfig.f1655e.getF8764j().f1628G != -1 && (m4795a02 = C4195m.m4795a0(itemView, DslTabLayoutConfig.this.f1655e.getF8764j().f1628G)) != null && (m4795a02 instanceof TextView)) {
                callback = m4795a02;
            }
            if (DslTabLayoutConfig.this.f1655e.getF8764j().f1629H != -1 && (findViewById2 = itemView.findViewById(DslTabLayoutConfig.this.f1655e.getF8764j().f1629H)) != null && (findViewById2 instanceof TextView)) {
                callback = findViewById2;
            }
            ViewGroup.LayoutParams layoutParams = itemView.getLayoutParams();
            if (layoutParams instanceof DslTabLayout.C3200a) {
                DslTabLayout.C3200a c3200a = (DslTabLayout.C3200a) layoutParams;
                int i3 = c3200a.f8784d;
                if (i3 != -1 && (itemView instanceof ViewGroup) && (m4795a0 = C4195m.m4795a0(itemView, i3)) != null && (m4795a0 instanceof TextView)) {
                    callback = m4795a0;
                }
                int i4 = c3200a.f8785e;
                if (i4 != -1 && (findViewById = itemView.findViewById(i4)) != null && (findViewById instanceof TextView)) {
                    callback = findViewById;
                }
            }
            return (TextView) callback;
        }
    }

    public DslTabLayoutConfig(@NotNull DslTabLayout tabLayout) {
        Intrinsics.checkNotNullParameter(tabLayout, "tabLayout");
        this.f1655e = tabLayout;
        this.f1656f = true;
        this.f1659i = -1;
        this.f1660j = Color.parseColor("#999999");
        this.f1662l = true;
        this.f1664n = -2;
        this.f1665o = -2;
        this.f1667q = 0.8f;
        this.f1668r = 1.2f;
        this.f1669s = true;
        this.f1670t = -1.0f;
        this.f1671u = -1.0f;
        this.f1672v = new TabGradientCallback();
        this.f1673w = -1;
        this.f1674x = -1;
        this.f1675y = new e();
        this.f1676z = new d();
        this.f1654A = new c();
        a aVar = new a();
        Intrinsics.checkNotNullParameter(aVar, "<set-?>");
        this.f1587a = aVar;
        b bVar = new b();
        Intrinsics.checkNotNullParameter(bVar, "<set-?>");
        this.f1589c = bVar;
    }

    /* renamed from: a */
    public void m683a(@Nullable View view, int i2, int i3, float f2) {
        Objects.requireNonNull(this.f1672v);
        TextView textView = view instanceof TextView ? (TextView) view : null;
        if (textView == null) {
            return;
        }
        textView.setTextColor(C4195m.m4789V(f2, i2, i3));
    }

    /* renamed from: b */
    public final int m684b() {
        int i2 = this.f1665o;
        return i2 == -2 ? this.f1660j : i2;
    }

    /* renamed from: c */
    public final int m685c() {
        int i2 = this.f1664n;
        return i2 == -2 ? this.f1659i : i2;
    }
}
