package com.jbzd.media.movecartoons.p396ui.dialog;

import android.annotation.SuppressLint;
import android.app.Dialog;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.DialogFragment;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
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
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u00002\u00020\u0001B5\u0012\b\b\u0002\u0010\u000b\u001a\u00020\n\u0012\b\b\u0002\u0010\u0015\u001a\u00020\n\u0012\b\b\u0002\u0010\u001a\u001a\u00020\n\u0012\u000e\b\u0002\u0010$\u001a\b\u0012\u0004\u0012\u00020#0\"¢\u0006\u0004\b3\u00104J\u000f\u0010\u0003\u001a\u00020\u0002H\u0003¢\u0006\u0004\b\u0003\u0010\u0004J\u0019\u0010\b\u001a\u00020\u00072\b\u0010\u0006\u001a\u0004\u0018\u00010\u0005H\u0016¢\u0006\u0004\b\b\u0010\tR\u0019\u0010\u000b\u001a\u00020\n8\u0006@\u0006¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000eR\u001d\u0010\u0014\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013R\u0019\u0010\u0015\u001a\u00020\n8\u0006@\u0006¢\u0006\f\n\u0004\b\u0015\u0010\f\u001a\u0004\b\u0016\u0010\u000eR\u001d\u0010\u0019\u001a\u00020\u00028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u0011\u001a\u0004\b\u0018\u0010\u0004R\u0019\u0010\u001a\u001a\u00020\n8\u0006@\u0006¢\u0006\f\n\u0004\b\u001a\u0010\f\u001a\u0004\b\u001b\u0010\u000eR%\u0010!\u001a\n \u001d*\u0004\u0018\u00010\u001c0\u001c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u0011\u001a\u0004\b\u001f\u0010 R\u001f\u0010$\u001a\b\u0012\u0004\u0012\u00020#0\"8\u0006@\u0006¢\u0006\f\n\u0004\b$\u0010%\u001a\u0004\b&\u0010'R\u001d\u0010,\u001a\u00020(8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0011\u001a\u0004\b*\u0010+R\u001d\u0010/\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0011\u001a\u0004\b.\u0010\u0013R\u001d\u00102\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u0011\u001a\u0004\b1\u0010\u0013¨\u00065"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/MovieBuyDialog;", "Landroidx/fragment/app/DialogFragment;", "Landroidx/appcompat/app/AlertDialog;", "createDialog", "()Landroidx/appcompat/app/AlertDialog;", "Landroid/os/Bundle;", "savedInstanceState", "Landroid/app/Dialog;", "onCreateDialog", "(Landroid/os/Bundle;)Landroid/app/Dialog;", "", "price", "Ljava/lang/String;", "getPrice", "()Ljava/lang/String;", "Landroid/widget/TextView;", "tv_goRecharge$delegate", "Lkotlin/Lazy;", "getTv_goRecharge", "()Landroid/widget/TextView;", "tv_goRecharge", "rate_price", "getRate_price", "alertDialog$delegate", "getAlertDialog", "alertDialog", "nickname", "getNickname", "Landroid/view/View;", "kotlin.jvm.PlatformType", "contentView$delegate", "getContentView", "()Landroid/view/View;", "contentView", "Lkotlin/Function0;", "", "buyVideo", "Lkotlin/jvm/functions/Function0;", "getBuyVideo", "()Lkotlin/jvm/functions/Function0;", "Landroid/widget/LinearLayout;", "ll_buy$delegate", "getLl_buy", "()Landroid/widget/LinearLayout;", "ll_buy", "tv_desc$delegate", "getTv_desc", "tv_desc", "tv_buyPrice$delegate", "getTv_buyPrice", "tv_buyPrice", "<init>", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function0;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieBuyDialog extends DialogFragment {

    /* renamed from: alertDialog$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy alertDialog;

    @NotNull
    private final Function0<Unit> buyVideo;

    /* renamed from: contentView$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentView;

    /* renamed from: ll_buy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_buy;

    @NotNull
    private final String nickname;

    @NotNull
    private final String price;

    @NotNull
    private final String rate_price;

    /* renamed from: tv_buyPrice$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_buyPrice;

    /* renamed from: tv_desc$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_desc;

    /* renamed from: tv_goRecharge$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_goRecharge;

    public MovieBuyDialog() {
        this(null, null, null, null, 15, null);
    }

    public /* synthetic */ MovieBuyDialog(String str, String str2, String str3, Function0 function0, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this((i2 & 1) != 0 ? "0" : str, (i2 & 2) != 0 ? "0" : str2, (i2 & 4) != 0 ? "" : str3, (i2 & 8) != 0 ? new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog.1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        } : function0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    @SuppressLint({"SetTextI18n"})
    public final AlertDialog createDialog() {
        double d2;
        AlertDialog m624j0 = C1499a.m624j0(new AlertDialog.Builder(requireContext(), R.style.dialog_center), getContentView(), "Builder(requireContext(), R.style.dialog_center)\n            .setView(contentView)\n            .create()");
        TextView tv_desc = getTv_desc();
        StringBuilder m586H = C1499a.m586H("VIP优惠价：");
        m586H.append(this.rate_price);
        m586H.append("钻石\n非会员价：");
        m586H.append(this.price);
        m586H.append("钻石\n支持原创，付费给#");
        m586H.append(this.nickname);
        m586H.append('#');
        tv_desc.setText(m586H.toString());
        double d3 = ShadowDrawableWrapper.COS_45;
        try {
            d2 = Double.parseDouble(this.price);
        } catch (Exception unused) {
            d2 = 0.0d;
        }
        try {
            Double.parseDouble(this.rate_price);
        } catch (Exception unused2) {
        }
        try {
            MyApp myApp = MyApp.f9891f;
            UserInfoBean userInfoBean = MyApp.f9892g;
            String str = userInfoBean == null ? null : userInfoBean.point;
            if (str != null) {
                d3 = Double.parseDouble(str);
            }
        } catch (Exception unused3) {
        }
        boolean z = d3 >= d2;
        getTv_buyPrice().setText(this.price);
        if (z) {
            getTv_goRecharge().setVisibility(8);
            getLl_buy().setVisibility(0);
        } else {
            getTv_goRecharge().setVisibility(0);
            getLl_buy().setVisibility(8);
        }
        C2354n.m2374A(getTv_goRecharge(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$createDialog$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MovieBuyDialog.this.dismissAllowingStateLoss();
                BuyActivity.Companion companion = BuyActivity.INSTANCE;
                Context requireContext = MovieBuyDialog.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        C2354n.m2533z(getLl_buy(), 2000L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$createDialog$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MovieBuyDialog.this.dismissAllowingStateLoss();
                MovieBuyDialog.this.getBuyVideo().invoke();
            }
        });
        Window window = m624j0.getWindow();
        if (window != null) {
            window.setDimAmount(0.0f);
        }
        WindowManager.LayoutParams attributes = window != null ? window.getAttributes() : null;
        if (attributes != null) {
            attributes.windowAnimations = R.style.BottomShowAnimation;
        }
        return m624j0;
    }

    private final AlertDialog getAlertDialog() {
        return (AlertDialog) this.alertDialog.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final View getContentView() {
        return (View) this.contentView.getValue();
    }

    private final LinearLayout getLl_buy() {
        return (LinearLayout) this.ll_buy.getValue();
    }

    private final TextView getTv_buyPrice() {
        return (TextView) this.tv_buyPrice.getValue();
    }

    private final TextView getTv_desc() {
        return (TextView) this.tv_desc.getValue();
    }

    private final TextView getTv_goRecharge() {
        return (TextView) this.tv_goRecharge.getValue();
    }

    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Function0<Unit> getBuyVideo() {
        return this.buyVideo;
    }

    @NotNull
    public final String getNickname() {
        return this.nickname;
    }

    @NotNull
    public final String getPrice() {
        return this.price;
    }

    @NotNull
    public final String getRate_price() {
        return this.rate_price;
    }

    @Override // androidx.fragment.app.DialogFragment
    @NotNull
    public Dialog onCreateDialog(@Nullable Bundle savedInstanceState) {
        return getAlertDialog();
    }

    public MovieBuyDialog(@NotNull String price, @NotNull String rate_price, @NotNull String nickname, @NotNull Function0<Unit> buyVideo) {
        Intrinsics.checkNotNullParameter(price, "price");
        Intrinsics.checkNotNullParameter(rate_price, "rate_price");
        Intrinsics.checkNotNullParameter(nickname, "nickname");
        Intrinsics.checkNotNullParameter(buyVideo, "buyVideo");
        this.price = price;
        this.rate_price = rate_price;
        this.nickname = nickname;
        this.buyVideo = buyVideo;
        this.contentView = LazyKt__LazyJVMKt.lazy(new Function0<View>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$contentView$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            public final View invoke() {
                return LayoutInflater.from(MovieBuyDialog.this.getContext()).inflate(R.layout.dialog_movie_buy, (ViewGroup) null);
            }
        });
        this.tv_desc = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$tv_desc$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = MovieBuyDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_desc);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.tv_goRecharge = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$tv_goRecharge$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = MovieBuyDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_goRecharge);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.ll_buy = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$ll_buy$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View contentView;
                contentView = MovieBuyDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.ll_buy);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.LinearLayout");
                return (LinearLayout) findViewById;
            }
        });
        this.tv_buyPrice = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$tv_buyPrice$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View contentView;
                contentView = MovieBuyDialog.this.getContentView();
                View findViewById = contentView.findViewById(R.id.tv_buyPrice);
                Objects.requireNonNull(findViewById, "null cannot be cast to non-null type android.widget.TextView");
                return (TextView) findViewById;
            }
        });
        this.alertDialog = LazyKt__LazyJVMKt.lazy(new Function0<AlertDialog>() { // from class: com.jbzd.media.movecartoons.ui.dialog.MovieBuyDialog$alertDialog$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final AlertDialog invoke() {
                AlertDialog createDialog;
                createDialog = MovieBuyDialog.this.createDialog();
                return createDialog;
            }
        });
    }
}
