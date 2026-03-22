package com.jbzd.media.movecartoons.p396ui.vip;

import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.text.SimpleDateFormat;
import java.util.Date;
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
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u001b\u0018\u0000 \"2\u00020\u0001:\u0001\"B\u0007¢\u0006\u0004\b!\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nR\u001d\u0010\u000e\u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\nR\u001d\u0010\u0011\u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000f\u0010\f\u001a\u0004\b\u0010\u0010\nR\u001d\u0010\u0014\u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\f\u001a\u0004\b\u0013\u0010\nR\u001d\u0010\u0017\u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0015\u0010\f\u001a\u0004\b\u0016\u0010\nR\u001d\u0010\u001a\u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\f\u001a\u0004\b\u0019\u0010\nR\u001d\u0010\u001d\u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\f\u001a\u0004\b\u001c\u0010\nR\u001d\u0010 \u001a\u00020\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\f\u001a\u0004\b\u001f\u0010\n¨\u0006#"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/PayingActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseActivity;", "", "bindEvent", "()V", "", "getLayoutId", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "payTips$delegate", "Lkotlin/Lazy;", "getPayTips", "payTips", "orderSn$delegate", "getOrderSn", "orderSn", "days$delegate", "getDays", "days", "payment$delegate", "getPayment", "payment", "icon$delegate", "getIcon", "icon", "price$delegate", "getPrice", "price", "name$delegate", "getName", "name", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PayingActivity extends BaseActivity {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: icon$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy icon = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$icon$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = PayingActivity.this.getIntent().getStringExtra("icon");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    /* renamed from: name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy name = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$name$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = PayingActivity.this.getIntent().getStringExtra("name");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    /* renamed from: price$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy price = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$price$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = PayingActivity.this.getIntent().getStringExtra("price");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    /* renamed from: payment$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy payment = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$payment$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = PayingActivity.this.getIntent().getStringExtra("payment");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    /* renamed from: days$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy days = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$days$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = PayingActivity.this.getIntent().getStringExtra("days");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    /* renamed from: orderSn$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy orderSn = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$orderSn$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = PayingActivity.this.getIntent().getStringExtra("orderSn");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    /* renamed from: payTips$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy payTips = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$payTips$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = PayingActivity.this.getIntent().getStringExtra("payTips");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\b\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0010\u0010\u0011Jc\u0010\u000e\u001a\u00020\r2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\b\u0010\u0006\u001a\u0004\u0018\u00010\u00042\b\u0010\u0007\u001a\u0004\u0018\u00010\u00042\b\u0010\b\u001a\u0004\u0018\u00010\u00042\b\u0010\t\u001a\u0004\u0018\u00010\u00042\b\u0010\n\u001a\u0004\u0018\u00010\u00042\b\u0010\u000b\u001a\u0004\u0018\u00010\u00042\b\u0010\f\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b\u000e\u0010\u000f¨\u0006\u0012"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/PayingActivity$Companion;", "", "Landroid/content/Context;", "context", "", "urlRouter", "icon", "price", "name", "payment", "days", "orderSn", "payTips", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull String urlRouter, @Nullable String icon, @Nullable String price, @Nullable String name, @Nullable String payment, @Nullable String days, @Nullable String orderSn, @Nullable String payTips) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(urlRouter, "urlRouter");
            Intent intent = new Intent(context, (Class<?>) PayingActivity.class);
            intent.putExtra("icon", icon);
            intent.putExtra("price", price);
            intent.putExtra("name", name);
            intent.putExtra("payment", payment);
            intent.putExtra("days", days);
            intent.putExtra("orderSn", orderSn);
            intent.putExtra("payTips", payTips);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    private final String getDays() {
        return (String) this.days.getValue();
    }

    private final String getIcon() {
        return (String) this.icon.getValue();
    }

    private final String getName() {
        return (String) this.name.getValue();
    }

    private final String getOrderSn() {
        return (String) this.orderSn.getValue();
    }

    private final String getPayTips() {
        return (String) this.payTips.getValue();
    }

    private final String getPayment() {
        return (String) this.payment.getValue();
    }

    private final String getPrice() {
        return (String) this.price.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        C2354n.m2467d2(this).m3298p(getIcon()).m3295i0().m757R((ImageView) findViewById(R$id.iv_paymentIcon));
        ((TextView) findViewById(R$id.tv_price)).setText(getPrice());
        ((TextView) findViewById(R$id.tv_name)).setText(getName());
        ((TextView) findViewById(R$id.tv_payment)).setText(getPayment());
        ((TextView) findViewById(R$id.tv_days)).setText(getDays());
        ((RelativeLayout) findViewById(R$id.rl_days)).setVisibility(TextUtils.isEmpty(getDays()) ^ true ? 0 : 8);
        ((TextView) findViewById(R$id.tv_orderSn)).setText(getOrderSn());
        TextView textView = (TextView) findViewById(R$id.tv_time);
        String format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date(System.currentTimeMillis()));
        Intrinsics.checkNotNullExpressionValue(format, "format.format(d1)");
        textView.setText(format);
        ((TextView) findViewById(R$id.tv_payTips)).setText(getPayTips());
        C2354n.m2374A((ProgressButton) findViewById(R$id.submit), 0L, new Function1<ProgressButton, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.PayingActivity$bindEvent$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ProgressButton progressButton) {
                invoke2(progressButton);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(ProgressButton progressButton) {
                PayingActivity.this.onBackPressed();
            }
        }, 1);
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_paying;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "";
    }
}
