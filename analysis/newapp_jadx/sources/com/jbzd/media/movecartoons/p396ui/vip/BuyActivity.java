package com.jbzd.media.movecartoons.p396ui.vip;

import android.content.Context;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.GroupBean;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.databinding.ActBuyBinding;
import com.jbzd.media.movecartoons.databinding.FragVipBinding;
import com.jbzd.media.movecartoons.p396ui.dialog.BuyVipBottomSheetDialog;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.vip.VipFragment;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMActivity;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0850i;
import p005b.p006a.p007a.p008a.p013o.C0909c;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u000f\u0018\u0000 92\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u00019B\u0007¢\u0006\u0004\b8\u0010\u0012J\u0017\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\tH\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u0017\u0010\u000f\u001a\u00020\u00062\u0006\u0010\u000e\u001a\u00020\rH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0013\u0010\u0012J\u000f\u0010\u0015\u001a\u00020\u0014H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0018\u001a\u00020\u0017H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u000f\u0010\u001b\u001a\u00020\u001aH\u0016¢\u0006\u0004\b\u001b\u0010\u001cR\"\u0010\u001d\u001a\u00020\t8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010 \"\u0004\b!\u0010\fR\u0018\u0010#\u001a\u0004\u0018\u00010\"8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b#\u0010$R\u001d\u0010*\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b&\u0010'\u001a\u0004\b(\u0010)R\"\u0010,\u001a\u00020+8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b,\u0010-\u001a\u0004\b.\u0010/\"\u0004\b0\u00101R\u001d\u00104\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b2\u0010'\u001a\u0004\b3\u0010)R\"\u00105\u001a\u00020+8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b5\u0010-\u001a\u0004\b6\u0010/\"\u0004\b7\u00101¨\u0006:"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/BuyActivity;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMActivity;", "Lcom/jbzd/media/movecartoons/databinding/ActBuyBinding;", "Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;", "Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;", "userInfo", "", "showUserInfo", "(Lcom/jbzd/media/movecartoons/bean/response/UserInfoBean;)V", "Lb/a/a/a/o/c;", "vipGroup", "showVipCard", "(Lb/a/a/a/o/c;)V", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "mGroupBean", "showPaymentDialog", "(Lcom/jbzd/media/movecartoons/bean/response/GroupBean;)V", "initView", "()V", "bindEvent", "", "immersionBar", "()Z", "", "backColor", "()I", "", "getTopBarTitle", "()Ljava/lang/String;", "mVipGroup", "Lb/a/a/a/o/c;", "getMVipGroup", "()Lb/a/a/a/o/c;", "setMVipGroup", "Lcom/jbzd/media/movecartoons/ui/dialog/BuyVipBottomSheetDialog;", "paymentDialog", "Lcom/jbzd/media/movecartoons/ui/dialog/BuyVipBottomSheetDialog;", "Landroid/widget/TextView;", "tv_open_vip$delegate", "Lkotlin/Lazy;", "getTv_open_vip", "()Landroid/widget/TextView;", "tv_open_vip", "Lcom/jbzd/media/movecartoons/ui/vip/VipFragment;", "mVipFragmentTwo", "Lcom/jbzd/media/movecartoons/ui/vip/VipFragment;", "getMVipFragmentTwo", "()Lcom/jbzd/media/movecartoons/ui/vip/VipFragment;", "setMVipFragmentTwo", "(Lcom/jbzd/media/movecartoons/ui/vip/VipFragment;)V", "tv_exchange_vip$delegate", "getTv_exchange_vip", "tv_exchange_vip", "mVipFragmentOne", "getMVipFragmentOne", "setMVipFragmentOne", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BuyActivity extends BaseVMActivity<ActBuyBinding, VipViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public VipFragment mVipFragmentOne;
    public VipFragment mVipFragmentTwo;
    public C0909c mVipGroup;

    @Nullable
    private BuyVipBottomSheetDialog paymentDialog;

    /* renamed from: tv_exchange_vip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_exchange_vip = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$tv_exchange_vip$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) BuyActivity.this.findViewById(R.id.tv_exchange_vip);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_open_vip$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_open_vip = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$tv_open_vip$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) BuyActivity.this.findViewById(R.id.tv_open_vip);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/BuyActivity$Companion;", "", "Landroid/content/Context;", "context", "", "start", "(Landroid/content/Context;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context) {
            C1499a.m602X(context, "context", context, BuyActivity.class);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final /* synthetic */ ActBuyBinding access$getBodyBinding(BuyActivity buyActivity) {
        return (ActBuyBinding) buyActivity.getBodyBinding();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showPaymentDialog(GroupBean mGroupBean) {
        if (this.paymentDialog == null) {
            BuyActivity mBuyActivity = VipFragment.INSTANCE.getMBuyActivity();
            this.paymentDialog = mBuyActivity == null ? null : BuyVipBottomSheetDialog.INSTANCE.getShareBottomSheetDialog(mBuyActivity, getViewModel());
        }
        BuyVipBottomSheetDialog buyVipBottomSheetDialog = this.paymentDialog;
        Intrinsics.checkNotNull(buyVipBottomSheetDialog);
        if (buyVipBottomSheetDialog.isShowing()) {
            return;
        }
        StringBuilder m586H = C1499a.m586H("支付");
        m586H.append((Object) mGroupBean.getPrice());
        m586H.append(".00元");
        mGroupBean.setButton_text(m586H.toString());
        BuyVipBottomSheetDialog buyVipBottomSheetDialog2 = this.paymentDialog;
        if (buyVipBottomSheetDialog2 != null) {
            List<GroupBean.PaymentsBean> payments = mGroupBean.getPayments();
            C0909c value = getViewModel().getInfoBean().getValue();
            buyVipBottomSheetDialog2.setVipShowData(payments, mGroupBean, value != null ? value.f366c : null);
        }
        BuyVipBottomSheetDialog buyVipBottomSheetDialog3 = this.paymentDialog;
        if (buyVipBottomSheetDialog3 == null) {
            return;
        }
        buyVipBottomSheetDialog3.show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showUserInfo(final UserInfoBean userInfo) {
        bodyBinding(new Function1<ActBuyBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$showUserInfo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActBuyBinding actBuyBinding) {
                invoke2(actBuyBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ActBuyBinding bodyBinding) {
                String string;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                ComponentCallbacks2C1553c.m739i(bodyBinding.imgAvatar).mo775h(UserInfoBean.this.img).mo1098y(R.drawable.ic_place_holder_circle_51).m757R(bodyBinding.imgAvatar);
                bodyBinding.txtName.setText(UserInfoBean.this.nickname);
                TextView textView = bodyBinding.txtVipTag;
                if (UserInfoBean.this.isVipUser()) {
                    string = UserInfoBean.this.group_name + ' ' + ((Object) UserInfoBean.this.group_end_time) + " 到期";
                } else {
                    string = this.getString(R.string.buy_vip_tips);
                }
                textView.setText(string);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public final void showVipCard(C0909c vipGroup) {
        setMVipGroup(vipGroup);
        String[] stringArray = getResources().getStringArray(R.array.vip_type);
        Intrinsics.checkNotNullExpressionValue(stringArray, "resources.getStringArray(R.array.vip_type)");
        VipFragment.Companion companion = VipFragment.INSTANCE;
        List<GroupBean> items = vipGroup.f364a.get(0).getItems();
        setMVipFragmentOne(companion.createVipFragment(this, items == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) items)));
        List<GroupBean> items2 = vipGroup.f365b.get(0).getItems();
        setMVipFragmentTwo(companion.createVipFragment(this, items2 != null ? CollectionsKt___CollectionsKt.toMutableList((Collection) items2) : null));
        ViewPager viewPager = ((ActBuyBinding) getBodyBinding()).viewpagerVipCard;
        FragmentManager supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        viewPager.setAdapter(new ViewPagerAdapter(supportFragmentManager, CollectionsKt__CollectionsKt.arrayListOf(getMVipFragmentOne(), getMVipFragmentTwo()), 0, 4, null));
        ((ActBuyBinding) getBodyBinding()).tabMembershipCard.m4011e(((ActBuyBinding) getBodyBinding()).viewpagerVipCard, stringArray);
        ((ActBuyBinding) getBodyBinding()).tabMembershipCard.setCurrentTab(1);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMActivity, com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public int backColor() {
        return R.color.white;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity, p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        viewModels(new BuyActivity$bindEvent$1(this));
    }

    @NotNull
    public final VipFragment getMVipFragmentOne() {
        VipFragment vipFragment = this.mVipFragmentOne;
        if (vipFragment != null) {
            return vipFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mVipFragmentOne");
        throw null;
    }

    @NotNull
    public final VipFragment getMVipFragmentTwo() {
        VipFragment vipFragment = this.mVipFragmentTwo;
        if (vipFragment != null) {
            return vipFragment;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mVipFragmentTwo");
        throw null;
    }

    @NotNull
    public final C0909c getMVipGroup() {
        C0909c c0909c = this.mVipGroup;
        if (c0909c != null) {
            return c0909c;
        }
        Intrinsics.throwUninitializedPropertyAccessException("mVipGroup");
        throw null;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    @NotNull
    public String getTopBarTitle() {
        String string = getString(R.string.buy_vip_center);
        Intrinsics.checkNotNullExpressionValue(string, "getString(R.string.buy_vip_center)");
        return string;
    }

    @NotNull
    public final TextView getTv_exchange_vip() {
        return (TextView) this.tv_exchange_vip.getValue();
    }

    @NotNull
    public final TextView getTv_open_vip() {
        return (TextView) this.tv_open_vip.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public boolean immersionBar() {
        return true;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseBindingActivity
    public void initView() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("object_type", "enter_buy_vip");
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "system/track", Object.class, m595Q, C0850i.f251c, null, false, false, null, false, 432);
        C2354n.m2374A(getTv_exchange_vip(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$initView$2
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
                ExchangeActivity.Companion.start(BuyActivity.this);
            }
        }, 1);
        C2354n.m2374A(getTv_open_vip(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$initView$3
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
                if (BuyActivity.access$getBodyBinding(BuyActivity.this).viewpagerVipCard.getCurrentItem() == 0) {
                    VipFragment mVipFragmentOne = BuyActivity.this.getMVipFragmentOne();
                    final BuyActivity buyActivity = BuyActivity.this;
                    mVipFragmentOne.bodyBinding(new Function1<FragVipBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$initView$3.1
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(FragVipBinding fragVipBinding) {
                            invoke2(fragVipBinding);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull FragVipBinding bodyBinding) {
                            Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                            Object realData = bodyBinding.banner.getAdapter().getRealData(bodyBinding.banner.getCurrentItem());
                            Objects.requireNonNull(realData, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.GroupBean");
                            BuyActivity.this.showPaymentDialog((GroupBean) realData);
                        }
                    });
                }
                if (BuyActivity.access$getBodyBinding(BuyActivity.this).viewpagerVipCard.getCurrentItem() == 1) {
                    VipFragment mVipFragmentTwo = BuyActivity.this.getMVipFragmentTwo();
                    final BuyActivity buyActivity2 = BuyActivity.this;
                    mVipFragmentTwo.bodyBinding(new Function1<FragVipBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$initView$3.2
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(FragVipBinding fragVipBinding) {
                            invoke2(fragVipBinding);
                            return Unit.INSTANCE;
                        }

                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                        public final void invoke2(@NotNull FragVipBinding bodyBinding) {
                            Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                            Object realData = bodyBinding.banner.getAdapter().getRealData(bodyBinding.banner.getCurrentItem());
                            Objects.requireNonNull(realData, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.GroupBean");
                            BuyActivity.this.showPaymentDialog((GroupBean) realData);
                        }
                    });
                }
            }
        }, 1);
        ((ImageView) getTitleLayout().findViewById(R.id.iv_titleLeftIcon)).setColorFilter(-1);
        ((TextView) getTitleLayout().findViewById(R.id.tv_title)).setTextColor(ContextCompat.getColor(this, R.color.white));
        bodyBinding(new Function1<ActBuyBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$initView$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ActBuyBinding actBuyBinding) {
                invoke2(actBuyBinding);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull final ActBuyBinding bodyBinding) {
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                BuyActivity.this.getTitleLayout().addOnLayoutChangeListener(new View.OnLayoutChangeListener() { // from class: com.jbzd.media.movecartoons.ui.vip.BuyActivity$initView$4.1
                    @Override // android.view.View.OnLayoutChangeListener
                    public void onLayoutChange(@NotNull View view, int left, int top, int right, int bottom, int oldLeft, int oldTop, int oldRight, int oldBottom) {
                        Intrinsics.checkNotNullParameter(view, "view");
                        if (bottom - top > 0) {
                            ConstraintLayout layoutVipHeader = ActBuyBinding.this.layoutVipHeader;
                            Intrinsics.checkNotNullExpressionValue(layoutVipHeader, "layoutVipHeader");
                            ViewGroup.LayoutParams layoutParams = layoutVipHeader.getLayoutParams();
                            Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
                            if (layoutParams instanceof ViewGroup.MarginLayoutParams) {
                                ((ViewGroup.MarginLayoutParams) layoutParams).topMargin = C4195m.m4785R(12.0f) + bottom;
                            }
                            layoutVipHeader.setLayoutParams(layoutParams);
                            view.removeOnLayoutChangeListener(this);
                        }
                    }
                });
                BuyActivity buyActivity = BuyActivity.this;
                MyApp myApp = MyApp.f9891f;
                buyActivity.showUserInfo(MyApp.f9892g);
            }
        });
    }

    public final void setMVipFragmentOne(@NotNull VipFragment vipFragment) {
        Intrinsics.checkNotNullParameter(vipFragment, "<set-?>");
        this.mVipFragmentOne = vipFragment;
    }

    public final void setMVipFragmentTwo(@NotNull VipFragment vipFragment) {
        Intrinsics.checkNotNullParameter(vipFragment, "<set-?>");
        this.mVipFragmentTwo = vipFragment;
    }

    public final void setMVipGroup(@NotNull C0909c c0909c) {
        Intrinsics.checkNotNullParameter(c0909c, "<set-?>");
        this.mVipGroup = c0909c;
    }
}
