package com.jbzd.media.movecartoons.p396ui.vip;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.res.Resources;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.appcompat.widget.ActivityChooserModel;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.Observer;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager2.widget.ViewPager2;
import com.drake.brv.BindingAdapter;
import com.drake.brv.annotaion.DividerOrientation;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.GroupBean;
import com.jbzd.media.movecartoons.bean.response.PayBean;
import com.jbzd.media.movecartoons.databinding.FragVipBinding;
import com.jbzd.media.movecartoons.p396ui.vip.VipFragment;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseVMFragment;
import com.youth.banner.Banner;
import com.youth.banner.adapter.BannerAdapter;
import com.youth.banner.listener.OnPageChangeListener;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function3;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0837b0;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p006a.p007a.p008a.p013o.C0908b;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0011\u0018\u0000 \u001e2\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001:\u0003\u001e\u001f B\u0007¢\u0006\u0004\b\u001d\u0010\u0006J\u000f\u0010\u0005\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u000e\u001a\u00020\r2\u0006\u0010\f\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0013\u0010\u0006J\u000f\u0010\u0014\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0014\u0010\u0006R\u0016\u0010\u0015\u001a\u00020\u00108\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0015\u0010\u0016R\"\u0010\u0017\u001a\u00020\r8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0017\u0010\u0018\u001a\u0004\b\u0019\u0010\u001a\"\u0004\b\u001b\u0010\u001c¨\u0006!"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/VipFragment;", "Lcom/qunidayede/supportlibrary/core/view/BaseVMFragment;", "Lcom/jbzd/media/movecartoons/databinding/FragVipBinding;", "Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;", "", "resetBannerHeight", "()V", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "groupBean", "showVipRights", "(Lcom/jbzd/media/movecartoons/bean/response/GroupBean;)V", "", "code", "", "getItemsIcon", "(Ljava/lang/String;)I", "", "useParentModel", "()Z", "initEvents", "initViews", "needResetHeight", "Z", "mPosition", "I", "getMPosition", "()I", "setMPosition", "(I)V", "<init>", "Companion", "VipItemAdapter", "VipItemViewHolder", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VipFragment extends BaseVMFragment<FragVipBinding, VipViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_VIP_CARD = "KEY_VIP_CARD";

    @Nullable
    private static BuyActivity mBuyActivity;
    private int mPosition;
    private boolean needResetHeight = true;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u000e\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0013\u0010\u0014J%\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\u000e\u0010\u0006\u001a\n\u0012\u0004\u0012\u00020\u0005\u0018\u00010\u0004¢\u0006\u0004\b\b\u0010\tR$\u0010\n\u001a\u0004\u0018\u00010\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR\u0016\u0010\u0011\u001a\u00020\u00108\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0011\u0010\u0012¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/VipFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/vip/BuyActivity;", ActivityChooserModel.ATTRIBUTE_ACTIVITY, "", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "vipCard", "Lcom/jbzd/media/movecartoons/ui/vip/VipFragment;", "createVipFragment", "(Lcom/jbzd/media/movecartoons/ui/vip/BuyActivity;Ljava/util/List;)Lcom/jbzd/media/movecartoons/ui/vip/VipFragment;", "mBuyActivity", "Lcom/jbzd/media/movecartoons/ui/vip/BuyActivity;", "getMBuyActivity", "()Lcom/jbzd/media/movecartoons/ui/vip/BuyActivity;", "setMBuyActivity", "(Lcom/jbzd/media/movecartoons/ui/vip/BuyActivity;)V", "", VipFragment.KEY_VIP_CARD, "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final VipFragment createVipFragment(@NotNull BuyActivity activity, @Nullable List<GroupBean> vipCard) {
            Intrinsics.checkNotNullParameter(activity, "activity");
            VipFragment vipFragment = new VipFragment();
            VipFragment.INSTANCE.setMBuyActivity(activity);
            Bundle bundle = new Bundle();
            Objects.requireNonNull(vipCard, "null cannot be cast to non-null type java.util.ArrayList<com.jbzd.media.movecartoons.bean.response.GroupBean>{ kotlin.collections.TypeAliasesKt.ArrayList<com.jbzd.media.movecartoons.bean.response.GroupBean> }");
            bundle.putParcelableArrayList(VipFragment.KEY_VIP_CARD, (ArrayList) vipCard);
            Unit unit = Unit.INSTANCE;
            vipFragment.setArguments(bundle);
            return vipFragment;
        }

        @Nullable
        public final BuyActivity getMBuyActivity() {
            return VipFragment.mBuyActivity;
        }

        public final void setMBuyActivity(@Nullable BuyActivity buyActivity) {
            VipFragment.mBuyActivity = buyActivity;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010!\n\u0002\b\u0005\b\u0002\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u001d\u0012\f\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u00020\u0016\u0012\u0006\u0010\u0018\u001a\u00020\u0011¢\u0006\u0004\b\u0019\u0010\u001aJ\u001f\u0010\b\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\b\u0010\tJ/\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\n\u001a\u00020\u00032\u0006\u0010\u000b\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000f\u0010\u0010R\u0019\u0010\u0012\u001a\u00020\u00118\u0006@\u0006¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0015¨\u0006\u001b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/VipFragment$VipItemAdapter;", "Lcom/youth/banner/adapter/BannerAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/GroupBean;", "Lcom/jbzd/media/movecartoons/ui/vip/VipFragment$VipItemViewHolder;", "Landroid/view/ViewGroup;", "parent", "", "viewType", "onCreateHolder", "(Landroid/view/ViewGroup;I)Lcom/jbzd/media/movecartoons/ui/vip/VipFragment$VipItemViewHolder;", "holder", "data", "position", "size", "", "onBindView", "(Lcom/jbzd/media/movecartoons/ui/vip/VipFragment$VipItemViewHolder;Lcom/jbzd/media/movecartoons/bean/response/GroupBean;II)V", "Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;", "viewModel", "Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;", "getViewModel", "()Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;", "", "dataList", "mViewModel", "<init>", "(Ljava/util/List;Lcom/jbzd/media/movecartoons/ui/vip/VipViewModel;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class VipItemAdapter extends BannerAdapter<GroupBean, VipItemViewHolder> {

        @NotNull
        private final VipViewModel viewModel;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public VipItemAdapter(@NotNull List<GroupBean> dataList, @NotNull VipViewModel mViewModel) {
            super(dataList);
            Intrinsics.checkNotNullParameter(dataList, "dataList");
            Intrinsics.checkNotNullParameter(mViewModel, "mViewModel");
            this.viewModel = mViewModel;
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* renamed from: onBindView$lambda-1$lambda-0, reason: not valid java name */
        public static final void m6018onBindView$lambda1$lambda0(GroupBean data, VipItemViewHolder holder, Integer num) {
            Intrinsics.checkNotNullParameter(data, "$data");
            Intrinsics.checkNotNullParameter(holder, "$holder");
            String end_time = data.getEnd_time();
            int parseInt = (end_time == null ? 0 : Integer.parseInt(end_time)) - (num == null ? 0 : num.intValue());
            if (parseInt > 0) {
                ((TextView) holder.itemView.findViewById(R.id.tv_time_vipcard_countdown)).setVisibility(0);
                String m183b = C0843e0.m183b(parseInt, "day");
                String m183b2 = C0843e0.m183b(parseInt, "hour");
                String m183b3 = C0843e0.m183b(parseInt, "min");
                String m183b4 = C0843e0.m183b(parseInt, "sec");
                String str = m183b + (char) 22825 + m183b2 + ':' + m183b3 + ':' + m183b4 + "后结束";
                if (TextUtils.equals("0", m183b)) {
                    str = "新人倒计时" + m183b2 + ':' + m183b3 + ':' + m183b4;
                }
                ((TextView) holder.itemView.findViewById(R.id.tv_time_vipcard_countdown)).setText(str);
            }
        }

        @NotNull
        public final VipViewModel getViewModel() {
            return this.viewModel;
        }

        @Override // com.youth.banner.holder.IViewHolder
        public void onBindView(@NotNull final VipItemViewHolder holder, @NotNull final GroupBean data, int position, int size) {
            String str;
            Intrinsics.checkNotNullParameter(holder, "holder");
            Intrinsics.checkNotNullParameter(data, "data");
            ImageView imageView = (ImageView) holder.itemView.findViewById(R.id.img_vip_icon);
            ApplicationC2828a context = C2827a.f7670a;
            if (context == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            Intrinsics.checkNotNullParameter(context, "context");
            try {
                PackageManager packageManager = context.getPackageManager();
                ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context.getPackageName(), 128);
                Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
                str = (String) packageManager.getApplicationLabel(applicationInfo);
            } catch (PackageManager.NameNotFoundException unused) {
                str = "";
            }
            boolean z = false;
            if (Intrinsics.areEqual(str != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(str, "九妖", false, 2, null)) : null, Boolean.TRUE)) {
                C2354n.m2459b2(imageView).m3298p(data.getImg()).m3291e0(R.drawable.ic_place_holder_horizontal).m757R(imageView);
            } else {
                C2354n.m2459b2(imageView).m3298p(data.getImg()).m3295i0().m3291e0(R.drawable.ic_place_holder_horizontal_51).m757R(imageView);
            }
            if (Intrinsics.areEqual(data.getEnd_time(), "0")) {
                ((TextView) holder.itemView.findViewById(R.id.tv_time_vipcard_countdown)).setVisibility(8);
                return;
            }
            ((TextView) holder.itemView.findViewById(R.id.tv_time_vipcard_countdown)).setVisibility(0);
            String valueOf = String.valueOf(data.getEnd_time());
            if (!TextUtils.isEmpty(valueOf)) {
                try {
                    Intrinsics.checkNotNull(valueOf);
                    if (Double.parseDouble(valueOf) > ShadowDrawableWrapper.COS_45) {
                        z = true;
                    }
                } catch (Exception unused2) {
                }
            }
            if (z) {
                getViewModel().getPassCount().observeForever(new Observer() { // from class: b.a.a.a.t.q.e
                    @Override // androidx.lifecycle.Observer
                    public final void onChanged(Object obj) {
                        VipFragment.VipItemAdapter.m6018onBindView$lambda1$lambda0(GroupBean.this, holder, (Integer) obj);
                    }
                });
            }
        }

        @Override // com.youth.banner.holder.IViewHolder
        @NotNull
        public VipItemViewHolder onCreateHolder(@NotNull ViewGroup parent, int viewType) {
            Intrinsics.checkNotNullParameter(parent, "parent");
            return new VipItemViewHolder(C4195m.m4803e0(parent, R.layout.item_card_vip));
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\b\u0002\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0004\u0010\u0005¨\u0006\u0006"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/vip/VipFragment$VipItemViewHolder;", "Landroidx/recyclerview/widget/RecyclerView$ViewHolder;", "Landroid/view/View;", "itemView", "<init>", "(Landroid/view/View;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class VipItemViewHolder extends RecyclerView.ViewHolder {
        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public VipItemViewHolder(@NotNull View itemView) {
            super(itemView);
            Intrinsics.checkNotNullParameter(itemView, "itemView");
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static final /* synthetic */ FragVipBinding access$getBodyBinding(VipFragment vipFragment) {
        return (FragVipBinding) vipFragment.getBodyBinding();
    }

    private final int getItemsIcon(String code) {
        return getResources().getIdentifier(Intrinsics.stringPlus("code_", code), "drawable", "com.jbzd.media.movecartoons");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-0, reason: not valid java name */
    public static final void m6017initEvents$lambda0(VipFragment this$0, PayBean buyResponse) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        FragmentActivity activity = this$0.requireActivity();
        Intrinsics.checkNotNullExpressionValue(activity, "requireActivity()");
        Intrinsics.checkNotNullExpressionValue(buyResponse, "it");
        VipFragment$initEvents$1$1 after = new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initEvents$1$1
            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
            }
        };
        Intrinsics.checkNotNullParameter(activity, "activity");
        Intrinsics.checkNotNullParameter(buyResponse, "buyResponse");
        Intrinsics.checkNotNullParameter(after, "after");
        if (Intrinsics.areEqual(buyResponse.type, "online")) {
            after.invoke();
            return;
        }
        if (Intrinsics.areEqual(buyResponse.type, "url")) {
            after.invoke();
            C0840d.a.m174d(C0840d.f235a, activity, buyResponse.url, null, null, 12);
        } else if (Intrinsics.areEqual(buyResponse.type, "alipay")) {
            String str = buyResponse.url;
            Intrinsics.checkNotNullExpressionValue(str, "buyResponse.url");
            C3109w0 c3109w0 = C3109w0.f8471c;
            C3079m0 c3079m0 = C3079m0.f8432c;
            C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new C0837b0(activity, str, after, null), 2, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public final void resetBannerHeight() {
        if (this.needResetHeight) {
            ((FragVipBinding) getBodyBinding()).banner.addOnLayoutChangeListener(new View.OnLayoutChangeListener() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$resetBannerHeight$1
                @Override // android.view.View.OnLayoutChangeListener
                public void onLayoutChange(@NotNull View view, int left, int top, int right, int bottom, int oldLeft, int oldTop, int oldRight, int oldBottom) {
                    int height;
                    Intrinsics.checkNotNullParameter(view, "view");
                    int i2 = bottom - top;
                    if (i2 > 0) {
                        view.removeOnLayoutChangeListener(this);
                        VipFragment.this.needResetHeight = false;
                        int currentItem = VipFragment.access$getBodyBinding(VipFragment.this).banner.getCurrentItem();
                        View childAt = ((ViewGroup) view).getChildAt(0);
                        Objects.requireNonNull(childAt, "null cannot be cast to non-null type androidx.viewpager2.widget.ViewPager2");
                        View childAt2 = ((ViewPager2) childAt).getChildAt(0);
                        Objects.requireNonNull(childAt2, "null cannot be cast to non-null type androidx.recyclerview.widget.RecyclerView");
                        RecyclerView.ViewHolder findViewHolderForAdapterPosition = ((RecyclerView) childAt2).findViewHolderForAdapterPosition(currentItem);
                        if (findViewHolderForAdapterPosition == null || (height = ((ImageView) findViewHolderForAdapterPosition.itemView.findViewById(R.id.img_vip_icon)).getHeight()) == i2) {
                            return;
                        }
                        ViewGroup.LayoutParams layoutParams = view.getLayoutParams();
                        Objects.requireNonNull(layoutParams, "null cannot be cast to non-null type android.view.ViewGroup.LayoutParams");
                        layoutParams.height = height;
                        view.setLayoutParams(layoutParams);
                    }
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showVipRights(final GroupBean groupBean) {
        bodyBinding(new Function1<FragVipBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$showVipRights$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                bodyBinding.tvVipRights.setText(GroupBean.this.getDescription());
                List<GroupBean.RightsBean> rights = GroupBean.this.getRights();
                List<? extends Object> list = null;
                Integer valueOf = rights == null ? null : Integer.valueOf(rights.size());
                Intrinsics.checkNotNull(valueOf);
                if (valueOf.intValue() > 0) {
                    RecyclerView listVipRights = bodyBinding.listVipRights;
                    Intrinsics.checkNotNullExpressionValue(listVipRights, "listVipRights");
                    BindingAdapter m4793Z = C4195m.m4793Z(listVipRights);
                    List<GroupBean.RightsBean> rights2 = GroupBean.this.getRights();
                    if (rights2 != null) {
                        VipFragment vipFragment = this;
                        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(rights2, 10));
                        for (GroupBean.RightsBean rightsBean : rights2) {
                            Resources resources = vipFragment.getResources();
                            String stringPlus = Intrinsics.stringPlus("icon_", rightsBean.getCode());
                            Context context = vipFragment.getContext();
                            arrayList.add(new C0908b(resources.getIdentifier(stringPlus, "drawable", context == null ? null : context.getPackageName()), rightsBean.getName(), null, 0, null, 28));
                        }
                        list = CollectionsKt___CollectionsKt.toList(arrayList);
                    }
                    Objects.requireNonNull(list, "null cannot be cast to non-null type kotlin.collections.List<com.jbzd.media.movecartoons.data.Items>");
                    m4793Z.m3939q(list);
                }
                RecyclerView listPayMethod = bodyBinding.listPayMethod;
                Intrinsics.checkNotNullExpressionValue(listPayMethod, "listPayMethod");
                C4195m.m4793Z(listPayMethod).m3926b(false);
                RecyclerView listPayMethod2 = bodyBinding.listPayMethod;
                Intrinsics.checkNotNullExpressionValue(listPayMethod2, "listPayMethod");
                C4195m.m4793Z(listPayMethod2).m3939q(GroupBean.this.getPayments());
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMFragment, com.qunidayede.supportlibrary.core.view.BaseBindingFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public final int getMPosition() {
        return this.mPosition;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        getViewModel().getPayBean().observe(getViewLifecycleOwner(), new Observer() { // from class: b.a.a.a.t.q.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                VipFragment.m6017initEvents$lambda0(VipFragment.this, (PayBean) obj);
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        getRootBinding().layoutRoot.setBackgroundColor(0);
        bodyBinding(new Function1<FragVipBinding, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1
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
                ArrayList parcelableArrayList;
                VipViewModel viewModel;
                Intrinsics.checkNotNullParameter(bodyBinding, "$this$bodyBinding");
                RecyclerView listVipRights = bodyBinding.listVipRights;
                Intrinsics.checkNotNullExpressionValue(listVipRights, "listVipRights");
                C4195m.m4821n0(listVipRights, 4, 0, false, false, 14);
                int m4785R = C4195m.m4785R(6.0f);
                DividerOrientation dividerOrientation = DividerOrientation.GRID;
                C4195m.m4784Q(listVipRights, m4785R, dividerOrientation);
                C4195m.m4774J0(listVipRights, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1.1
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                        boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", C0908b.class);
                        final int i2 = R.layout.item_member_rights;
                        if (m616f0) {
                            bindingAdapter.f8910l.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1$1$invoke$$inlined$addType$1
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
                            bindingAdapter.f8909k.put(Reflection.typeOf(C0908b.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1$1$invoke$$inlined$addType$2
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
                RecyclerView listPayMethod = bodyBinding.listPayMethod;
                Intrinsics.checkNotNullExpressionValue(listPayMethod, "listPayMethod");
                C4195m.m4821n0(listPayMethod, 3, 0, false, false, 14);
                C4195m.m4784Q(listPayMethod, C4195m.m4785R(12.0f), dividerOrientation);
                C4195m.m4774J0(listPayMethod, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1.2
                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                        invoke2(bindingAdapter, recyclerView);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull final BindingAdapter setup, @NotNull RecyclerView it) {
                        Intrinsics.checkNotNullParameter(setup, "$this$setup");
                        Intrinsics.checkNotNullParameter(it, "it");
                        setup.m3940r(true);
                        boolean isInterface = Modifier.isInterface(GroupBean.PaymentsBean.class.getModifiers());
                        final int i2 = R.layout.item_pay_type_vertical;
                        if (isInterface) {
                            setup.f8910l.put(Reflection.typeOf(GroupBean.PaymentsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1$2$invoke$$inlined$addType$1
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
                            setup.f8909k.put(Reflection.typeOf(GroupBean.PaymentsBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1$2$invoke$$inlined$addType$2
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
                        setup.m3937n(new int[]{R.id.root}, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment.initViews.1.2.1
                            {
                                super(2);
                            }

                            @Override // kotlin.jvm.functions.Function2
                            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                                invoke(bindingViewHolder, num.intValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                                Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                                if (((GroupBean.PaymentsBean) onClick.m3942b()).getIsChecked()) {
                                    return;
                                }
                                BindingAdapter.this.m3938o(onClick.getLayoutPosition(), true);
                            }
                        });
                        setup.m3936m(new Function3<Integer, Boolean, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment.initViews.1.2.2
                            {
                                super(3);
                            }

                            @Override // kotlin.jvm.functions.Function3
                            public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool, Boolean bool2) {
                                invoke(num.intValue(), bool.booleanValue(), bool2.booleanValue());
                                return Unit.INSTANCE;
                            }

                            public final void invoke(int i3, boolean z, boolean z2) {
                                ((GroupBean.PaymentsBean) BindingAdapter.this.m3930g(i3)).setChecked(z);
                                BindingAdapter.this.notifyItemChanged(i3);
                            }
                        });
                    }
                });
                VipFragment.this.resetBannerHeight();
                Banner banner = bodyBinding.banner;
                final VipFragment vipFragment = VipFragment.this;
                Bundle arguments = vipFragment.getArguments();
                if (arguments != null && (parcelableArrayList = arguments.getParcelableArrayList("KEY_VIP_CARD")) != null) {
                    viewModel = vipFragment.getViewModel();
                    banner.setAdapter(new VipFragment.VipItemAdapter(parcelableArrayList, viewModel));
                    Object obj = parcelableArrayList.get(0);
                    Intrinsics.checkNotNullExpressionValue(obj, "it[0]");
                    vipFragment.showVipRights((GroupBean) obj);
                }
                banner.setBannerGalleryEffect(24, 8, 0.9f);
                banner.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.vip.VipFragment$initViews$1$3$2
                    @Override // com.youth.banner.listener.OnPageChangeListener
                    public void onPageScrollStateChanged(int state) {
                    }

                    @Override // com.youth.banner.listener.OnPageChangeListener
                    public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                    }

                    @Override // com.youth.banner.listener.OnPageChangeListener
                    public void onPageSelected(int position) {
                        GroupBean groupBean;
                        VipFragment.this.setMPosition(position);
                        Bundle arguments2 = VipFragment.this.getArguments();
                        ArrayList parcelableArrayList2 = arguments2 == null ? null : arguments2.getParcelableArrayList("KEY_VIP_CARD");
                        if (parcelableArrayList2 == null || (groupBean = (GroupBean) parcelableArrayList2.get(position)) == null) {
                            return;
                        }
                        VipFragment.this.showVipRights(groupBean);
                    }
                });
                banner.setCurrentItem(0);
            }
        });
    }

    public final void setMPosition(int i2) {
        this.mPosition = i2;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseVMFragment
    public boolean useParentModel() {
        return true;
    }
}
