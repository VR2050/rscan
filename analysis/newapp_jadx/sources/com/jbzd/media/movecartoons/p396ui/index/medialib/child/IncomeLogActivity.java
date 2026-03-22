package com.jbzd.media.movecartoons.p396ui.index.medialib.child;

import android.content.Context;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.drake.brv.annotaion.DividerOrientation;
import com.drake.brv.utils.C1867b;
import com.jbzd.media.movecartoons.bean.response.IncomeLogBean;
import com.jbzd.media.movecartoons.databinding.ActPageBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseBindingActivity;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.InterfaceC0921e;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p383b2.InterfaceC3006b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0006\u0018\u0000 \u000b2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u000bB\u0007¢\u0006\u0004\b\n\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\t\u0010\b¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/IncomeLogActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseBindingActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActPageBinding;", "", "getTopBarTitle", "()Ljava/lang/String;", "", "bindEvent", "()V", "initView", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class IncomeLogActivity extends BaseBindingActivity<ActPageBinding> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/medialib/child/IncomeLogActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, IncomeLogActivity.class);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        C2354n.m2441W0(((InterfaceC0921e) LazyKt__LazyJVMKt.lazy(C0944a.a.f472c).getValue()).m245d(1), this, new Function1<List<IncomeLogBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.IncomeLogActivity$bindEvent$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<IncomeLogBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull List<IncomeLogBean> lifecycleLoadingDialog) {
                ActPageBinding bodyBinding;
                Intrinsics.checkNotNullParameter(lifecycleLoadingDialog, "$this$lifecycleLoadingDialog");
                bodyBinding = IncomeLogActivity.this.getBodyBinding();
                PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                PageRefreshLayout.m3951z(pageRefreshLayout, lifecycleLoadingDialog, null, null, null, 14, null);
            }
        }, false, new Function1<Throwable, Boolean>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.IncomeLogActivity$bindEvent$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Boolean invoke(Throwable th) {
                return Boolean.valueOf(invoke2(th));
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final boolean invoke2(@NotNull Throwable it) {
                ActPageBinding bodyBinding;
                Intrinsics.checkNotNullParameter(it, "it");
                bodyBinding = IncomeLogActivity.this.getBodyBinding();
                PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                PageRefreshLayout.m3950G(pageRefreshLayout, null, false, 3, null);
                return true;
            }
        }, 4);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.promotion_benefit);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.promotion_benefit)");
        return string;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new Function1<ActPageBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.IncomeLogActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActPageBinding actPageBinding) {
                invoke2(actPageBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull final ActPageBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                RecyclerView list = bodyBinding.list;
                Intrinsics.checkNotNullExpressionValue(list, "list");
                C4195m.m4835u0(list, 0, false, false, false, 15);
                DividerOrientation orientation = DividerOrientation.HORIZONTAL;
                Intrinsics.checkNotNullParameter(list, "<this>");
                Intrinsics.checkNotNullParameter(orientation, "orientation");
                C4195m.m4783P(list, new C1867b(R.drawable.divider_list, orientation));
                C4195m.m4774J0(list, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.IncomeLogActivity$initView$1.1
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", IncomeLogBean.class);
                        final int i2 = R.layout.item_income_log;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(IncomeLogBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.IncomeLogActivity$initView$1$1$invoke$$inlined$addType$1
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        } else {
                            bindingAdapter.f8909k.put(Reflection.typeOf(IncomeLogBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.IncomeLogActivity$initView$1$1$invoke$$inlined$addType$2
                                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                {
                                    super(2);
                                }

                                @NotNull
                                public final Integer invoke(@NotNull Object obj, int i3) {
                                    Intrinsics.checkNotNullParameter(obj, "$this$null");
                                    return Integer.valueOf(i2);
                                }

                                @Override // kotlin.jvm.functions.Function2
                                public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                                    return invoke(obj, num.intValue());
                                }
                            });
                        }
                    }
                });
                PageRefreshLayout pageRefreshLayout = bodyBinding.pager;
                final IncomeLogActivity incomeLogActivity = IncomeLogActivity.this;
                pageRefreshLayout.m3954D(new Function1<PageRefreshLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.medialib.child.IncomeLogActivity$initView$1.2
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull PageRefreshLayout onRefresh) {
                        Intrinsics.checkNotNullParameter(onRefresh, "$this$onRefresh");
                        Lazy lazy = LazyKt__LazyJVMKt.lazy(C0944a.a.f472c);
                        InterfaceC3006b<List<IncomeLogBean>> m245d = ((InterfaceC0921e) lazy.getValue()).m245d(onRefresh.getF8947T0());
                        IncomeLogActivity incomeLogActivity2 = IncomeLogActivity.this;
                        PageRefreshLayout pager = bodyBinding.pager;
                        Intrinsics.checkNotNullExpressionValue(pager, "pager");
                        C2354n.m2447Y0(m245d, incomeLogActivity2, pager, null, 4);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(PageRefreshLayout pageRefreshLayout2) {
                        invoke2(pageRefreshLayout2);
                        return Unit.INSTANCE;
                    }
                });
            }
        });
    }
}
