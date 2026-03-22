package com.jbzd.media.movecartoons.p396ui.wallet;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.OrderBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.chat.ChatDetailActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\f\u0018\u0000 %2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001%B\u0007¢\u0006\u0004\b$\u0010\rJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\tH\u0016¢\u0006\u0004\b\f\u0010\rJ3\u0010\u0013\u001a\u00020\t2\u0012\u0010\u000f\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00060\u000e2\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0012\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0016\u001a\u00020\u0015H\u0016¢\u0006\u0004\b\u0016\u0010\u0017R9\u0010\u001f\u001a\u001e\u0012\u0004\u0012\u00020\u0019\u0012\u0004\u0012\u00020\u00190\u0018j\u000e\u0012\u0004\u0012\u00020\u0019\u0012\u0004\u0012\u00020\u0019`\u001a8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u001c\u001a\u0004\b\u001d\u0010\u001eR\u001d\u0010#\u001a\u00020\u00198B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u001c\u001a\u0004\b!\u0010\"¨\u0006&"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/OrderListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/OrderBean;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/OrderBean;)V", "registerItemChildEvent", "()V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemChildClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "body$delegate", "Lkotlin/Lazy;", "getBody", "()Ljava/util/HashMap;", "body", "urlRouter$delegate", "getUrlRouter", "()Ljava/lang/String;", "urlRouter", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class OrderListFragment extends BaseListFragment<OrderBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: body$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy body = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.wallet.OrderListFragment$body$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return new HashMap<>();
        }
    });

    /* renamed from: urlRouter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy urlRouter = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.wallet.OrderListFragment$urlRouter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String string;
            Bundle arguments = OrderListFragment.this.getArguments();
            return (arguments == null || (string = arguments.getString("url")) == null) ? "" : string;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/OrderListFragment$Companion;", "", "", "urlRouter", "Lcom/jbzd/media/movecartoons/ui/wallet/OrderListFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/wallet/OrderListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final OrderListFragment newInstance(@NotNull String urlRouter) {
            Intrinsics.checkNotNullParameter(urlRouter, "urlRouter");
            OrderListFragment orderListFragment = new OrderListFragment();
            Bundle bundle = new Bundle();
            bundle.putString("url", urlRouter);
            Unit unit = Unit.INSTANCE;
            orderListFragment.setArguments(bundle);
            return orderListFragment;
        }
    }

    private final HashMap<String, String> getBody() {
        return (HashMap) this.body.getValue();
    }

    private final String getUrlRouter() {
        return (String) this.urlRouter.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_order;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemChildClick(@NotNull BaseQuickAdapter<OrderBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemChildClick(adapter, view, position);
        OrderBean orderBean = adapter.getData().get(position);
        ChatDetailActivity.Companion companion = ChatDetailActivity.INSTANCE;
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        ChatDetailActivity.Companion.start$default(companion, requireContext, null, null, orderBean.order_sn, orderBean.price, 6, null);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        registerItemChildClick(R.id.tv_vip_buy_tips);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        getBody().put("page", String.valueOf(getCurrentPage()));
        String urlRouter = getUrlRouter();
        HashMap<String, String> body = getBody();
        C0917a c0917a = C0917a.f372a;
        Intrinsics.checkNotNullExpressionValue(urlRouter, "urlRouter");
        return C0917a.m222f(c0917a, urlRouter, OrderBean.class, body, new Function1<List<? extends OrderBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.OrderListFragment$request$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends OrderBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends OrderBean> list) {
                OrderListFragment.this.didRequestComplete(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.OrderListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                OrderListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull OrderBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        helper.m3919i(R.id.tv_name, String.valueOf(item.group_name));
        helper.m3919i(R.id.tv_payment, Intrinsics.stringPlus("支付方式：", item.pay_name));
        helper.m3919i(R.id.tv_sn, Intrinsics.stringPlus("订单号：", item.order_sn));
        StringBuilder sb = new StringBuilder();
        sb.append((char) 165);
        sb.append((Object) item.price);
        sb.append((char) 20803);
        helper.m3919i(R.id.tv_money, sb.toString());
        helper.m3919i(R.id.tv_time, Intrinsics.stringPlus("交易起时间：", item.created_at));
        helper.m3919i(R.id.tv_days, Intrinsics.stringPlus("会员天数：", item.days));
        helper.m3916f(R.id.tv_days, TextUtils.equals(getUrlRouter(), "balanceGroup/orderList") || TextUtils.isEmpty(item.days));
        if (item.getIsSuccess()) {
            helper.m3919i(R.id.tv_status, "支付成功");
            helper.m3915e(R.id.tv_status, R.drawable.order_status_succes);
        } else {
            helper.m3919i(R.id.tv_status, "未支付");
            helper.m3915e(R.id.tv_status, R.drawable.order_status_fail);
        }
        helper.m3916f(R.id.tv_vip_buy_tips, item.getIsSuccess());
    }
}
