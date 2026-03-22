package com.angcyo.tablayout;

import android.view.View;
import com.luck.picture.lib.config.PictureConfig;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\b\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010 \n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0016\u0018\u00002\u00020\u0001B\u0005¢\u0006\u0002\u0010\u0002R\u001a\u0010\u0003\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u0005\u0010\u0006\"\u0004\b\u0007\u0010\bR\u001a\u0010\t\u001a\u00020\u0004X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\n\u0010\u0006\"\u0004\b\u000b\u0010\bR\u001a\u0010\f\u001a\u00020\rX\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011Rz\u0010\u0012\u001ab\u0012\u0013\u0012\u00110\u0004¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u0016\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020\u00040\u0017¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u0018\u0012\u0013\u0012\u00110\r¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u0019\u0012\u0013\u0012\u00110\r¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u001b0\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b\u001c\u0010\u001d\"\u0004\b\u001e\u0010\u001fRt\u0010 \u001a\\\u0012\u0013\u0012\u00110!¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\"\u0012\u0013\u0012\u00110\u0004¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(#\u0012\u0013\u0012\u00110\r¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b($\u0012\u0013\u0012\u00110\r¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\r0\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b%\u0010\u001d\"\u0004\b&\u0010\u001fR|\u0010'\u001ad\u0012\u0015\u0012\u0013\u0018\u00010!¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b((\u0012\u0019\u0012\u0017\u0012\u0004\u0012\u00020!0\u0017¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b()\u0012\u0013\u0012\u00110\r¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u0019\u0012\u0013\u0012\u00110\r¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\u001a\u0012\u0004\u0012\u00020\u001b0\u0013X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b*\u0010\u001d\"\u0004\b+\u0010\u001fR_\u0010,\u001aG\u0012\u0013\u0012\u00110!¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(\"\u0012\u0013\u0012\u00110\u0004¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b(#\u0012\u0013\u0012\u00110\r¢\u0006\f\b\u0014\u0012\b\b\u0015\u0012\u0004\b\b($\u0012\u0004\u0012\u00020\u001b0-X\u0086\u000e¢\u0006\u000e\n\u0000\u001a\u0004\b.\u0010/\"\u0004\b0\u00101¨\u00062"}, m5311d2 = {"Lcom/angcyo/tablayout/DslSelectorConfig;", "", "()V", "dslMaxSelectLimit", "", "getDslMaxSelectLimit", "()I", "setDslMaxSelectLimit", "(I)V", "dslMinSelectLimit", "getDslMinSelectLimit", "setDslMinSelectLimit", "dslMultiMode", "", "getDslMultiMode", "()Z", "setDslMultiMode", "(Z)V", "onSelectIndexChange", "Lkotlin/Function4;", "Lkotlin/ParameterName;", "name", "fromIndex", "", "selectIndexList", "reselect", "fromUser", "", "getOnSelectIndexChange", "()Lkotlin/jvm/functions/Function4;", "setOnSelectIndexChange", "(Lkotlin/jvm/functions/Function4;)V", "onSelectItemView", "Landroid/view/View;", "itemView", "index", "select", "getOnSelectItemView", "setOnSelectItemView", "onSelectViewChange", "fromView", "selectViewList", "getOnSelectViewChange", "setOnSelectViewChange", "onStyleItemView", "Lkotlin/Function3;", "getOnStyleItemView", "()Lkotlin/jvm/functions/Function3;", "setOnStyleItemView", "(Lkotlin/jvm/functions/Function3;)V", "TabLayout_release"}, m5312k = 1, m5313mv = {1, 6, 0}, m5315xi = 48)
/* renamed from: b.e.a.i, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public class DslSelectorConfig {

    /* renamed from: a */
    @NotNull
    public Function3<? super View, ? super Integer, ? super Boolean, Unit> f1587a = d.f1594c;

    /* renamed from: b */
    @NotNull
    public Function4<? super View, ? super List<? extends View>, ? super Boolean, ? super Boolean, Unit> f1588b = c.f1593c;

    /* renamed from: c */
    @NotNull
    public Function4<? super Integer, ? super List<Integer>, ? super Boolean, ? super Boolean, Unit> f1589c = a.f1591c;

    /* renamed from: d */
    @NotNull
    public Function4<? super View, ? super Integer, ? super Boolean, ? super Boolean, Boolean> f1590d = b.f1592c;

    @Metadata(m5310d1 = {"\u0000\u001c\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0007H\n¢\u0006\u0002\b\t"}, m5311d2 = {"<anonymous>", "", "fromIndex", "", PictureConfig.EXTRA_SELECT_LIST, "", "reselect", "", "fromUser", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.i$a */
    public static final class a extends Lambda implements Function4<Integer, List<? extends Integer>, Boolean, Boolean, Unit> {

        /* renamed from: c */
        public static final a f1591c = new a();

        public a() {
            super(4);
        }

        @Override // kotlin.jvm.functions.Function4
        public Unit invoke(Integer num, List<? extends Integer> list, Boolean bool, Boolean bool2) {
            int intValue = num.intValue();
            List<? extends Integer> selectList = list;
            boolean booleanValue = bool.booleanValue();
            boolean booleanValue2 = bool2.booleanValue();
            Intrinsics.checkNotNullParameter(selectList, "selectList");
            C4195m.m4837v0("选择:[" + intValue + "]->" + selectList + " reselect:" + booleanValue + " fromUser:" + booleanValue2);
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u0016\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0004\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00012\u0006\u0010\u0007\u001a\u00020\u0001H\n¢\u0006\u0004\b\b\u0010\t"}, m5311d2 = {"<anonymous>", "", "<anonymous parameter 0>", "Landroid/view/View;", "<anonymous parameter 1>", "", "<anonymous parameter 2>", "<anonymous parameter 3>", "invoke", "(Landroid/view/View;IZZ)Ljava/lang/Boolean;"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.i$b */
    public static final class b extends Lambda implements Function4<View, Integer, Boolean, Boolean, Boolean> {

        /* renamed from: c */
        public static final b f1592c = new b();

        public b() {
            super(4);
        }

        @Override // kotlin.jvm.functions.Function4
        public Boolean invoke(View view, Integer num, Boolean bool, Boolean bool2) {
            View noName_0 = view;
            num.intValue();
            bool.booleanValue();
            bool2.booleanValue();
            Intrinsics.checkNotNullParameter(noName_0, "$noName_0");
            return Boolean.FALSE;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u001c\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\u0010\u0000\u001a\u00020\u00012\b\u0010\u0002\u001a\u0004\u0018\u00010\u00032\f\u0010\u0004\u001a\b\u0012\u0004\u0012\u00020\u00030\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\b\u001a\u00020\u0007H\n¢\u0006\u0002\b\t"}, m5311d2 = {"<anonymous>", "", "<anonymous parameter 0>", "Landroid/view/View;", "<anonymous parameter 1>", "", "<anonymous parameter 2>", "", "<anonymous parameter 3>", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.i$c */
    public static final class c extends Lambda implements Function4<View, List<? extends View>, Boolean, Boolean, Unit> {

        /* renamed from: c */
        public static final c f1593c = new c();

        public c() {
            super(4);
        }

        @Override // kotlin.jvm.functions.Function4
        public Unit invoke(View view, List<? extends View> list, Boolean bool, Boolean bool2) {
            List<? extends View> noName_1 = list;
            bool.booleanValue();
            bool2.booleanValue();
            Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
            return Unit.INSTANCE;
        }
    }

    @Metadata(m5310d1 = {"\u0000\u001a\n\u0000\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u000b\n\u0000\u0010\u0000\u001a\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\n¢\u0006\u0002\b\b"}, m5311d2 = {"<anonymous>", "", "<anonymous parameter 0>", "Landroid/view/View;", "<anonymous parameter 1>", "", "<anonymous parameter 2>", "", "invoke"}, m5312k = 3, m5313mv = {1, 6, 0}, m5315xi = 48)
    /* renamed from: b.e.a.i$d */
    public static final class d extends Lambda implements Function3<View, Integer, Boolean, Unit> {

        /* renamed from: c */
        public static final d f1594c = new d();

        public d() {
            super(3);
        }

        @Override // kotlin.jvm.functions.Function3
        public Unit invoke(View view, Integer num, Boolean bool) {
            View noName_0 = view;
            num.intValue();
            bool.booleanValue();
            Intrinsics.checkNotNullParameter(noName_0, "$noName_0");
            return Unit.INSTANCE;
        }
    }
}
