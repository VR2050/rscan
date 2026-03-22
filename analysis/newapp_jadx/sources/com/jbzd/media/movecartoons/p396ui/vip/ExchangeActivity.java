package com.jbzd.media.movecartoons.p396ui.vip;

import android.content.Context;
import androidx.recyclerview.widget.RecyclerView;
import com.drake.brv.BindingAdapter;
import com.drake.brv.PageRefreshLayout;
import com.jbzd.media.movecartoons.bean.response.ExchangeLogBean;
import com.jbzd.media.movecartoons.databinding.ActExchangeBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p017r.p021n.C0944a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.p383b2.InterfaceC3006b;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 \u00122\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0001\u0012B\u0007¢\u0006\u0004\b\u0011\u0010\u0006J\u000f\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\u0006J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nR\u001d\u0010\u0010\u001a\u00020\u000b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000f¨\u0006\u0013"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/ExchangeActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActExchangeBinding;", "Lcom/jbzd/media/movecartoons/ui/vip/ExchangeViewModel;", "", "initView", "()V", "bindEvent", "", "getTopBarTitle", "()Ljava/lang/String;", "Landroidx/recyclerview/widget/RecyclerView;", "rv_exchange$delegate", "Lkotlin/Lazy;", "getRv_exchange", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_exchange", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ExchangeActivity extends BaseVMActivity<ActExchangeBinding, ExchangeViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: rv_exchange$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_exchange = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeActivity$rv_exchange$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) ExchangeActivity.this.findViewById(R.id.rv_exchange);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/ExchangeActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, ExchangeActivity.class);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final /* synthetic */ ActExchangeBinding access$getBodyBinding(ExchangeActivity exchangeActivity) {
        return (ActExchangeBinding) exchangeActivity.getBodyBinding();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        InterfaceC3006b<List<ExchangeLogBean>> m251j = getViewModel().getRepository().m287a().m251j(1);
        PageRefreshLayout pageRefreshLayout = ((ActExchangeBinding) getBodyBinding()).pager;
        Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
        C2354n.m2447Y0(m251j, this, pageRefreshLayout, null, 4);
    }

    @NotNull
    public final RecyclerView getRv_exchange() {
        return (RecyclerView) this.rv_exchange.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.exchange_vip);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.exchange_vip)");
        return string;
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        bodyBinding(new Function1<ActExchangeBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeActivity$initView$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActExchangeBinding actExchangeBinding) {
                invoke2(actExchangeBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActExchangeBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                RecyclerView rv_exchange = ExchangeActivity.this.getRv_exchange();
                C4195m.m4835u0(rv_exchange, 0, false, false, false, 15);
                C4195m.m4774J0(rv_exchange, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeActivity$initView$1.1
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", ExchangeLogBean.class);
                        final int i2 = R.layout.item_exchange;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(ExchangeLogBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeActivity$initView$1$1$invoke$$inlined$addType$1
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
                            bindingAdapter.f8909k.put(Reflection.typeOf(ExchangeLogBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeActivity$initView$1$1$invoke$$inlined$addType$2
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
            }
        });
        ((ActExchangeBinding) getBodyBinding()).pager.m3954D(new Function1<PageRefreshLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.ExchangeActivity$initView$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PageRefreshLayout pageRefreshLayout) {
                invoke2(pageRefreshLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull PageRefreshLayout onRefresh) {
                Intrinsics.checkNotNullParameter(onRefresh, "$this$onRefresh");
                C0944a repository = ExchangeActivity.this.getViewModel().getRepository();
                InterfaceC3006b<List<ExchangeLogBean>> m251j = repository.m287a().m251j(onRefresh.getF8947T0());
                ExchangeActivity exchangeActivity = ExchangeActivity.this;
                PageRefreshLayout pageRefreshLayout = ExchangeActivity.access$getBodyBinding(exchangeActivity).pager;
                Intrinsics.checkNotNullExpressionValue(pageRefreshLayout, "bodyBinding.pager");
                C2354n.m2447Y0(m251j, exchangeActivity, pageRefreshLayout, null, 4);
            }
        });
    }
}
