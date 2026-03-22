package com.jbzd.media.movecartoons.p396ui.wallet;

import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.badge.BadgeDrawable;
import com.jbzd.media.movecartoons.bean.response.BillBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.view.XDividerItemDecoration;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\u0018\u0000 \u00142\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u0014B\u0007¢\u0006\u0004\b\u0012\u0010\u0013J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011¨\u0006\u0015"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/BillListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/BillBean;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/BillBean;)V", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Lc/a/d1;", "request", "()Lc/a/d1;", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BillListFragment extends BaseListFragment<BillBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004¨\u0006\u0007"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/wallet/BillListFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/ui/wallet/BillListFragment;", "newInstance", "()Lcom/jbzd/media/movecartoons/ui/wallet/BillListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final BillListFragment newInstance() {
            return new BillListFragment();
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.ItemDecoration getItemDecoration() {
        XDividerItemDecoration xDividerItemDecoration = new XDividerItemDecoration(getContext(), 1);
        xDividerItemDecoration.setDrawable(getResources().getDrawable(R.drawable.bg_transaction));
        return xDividerItemDecoration;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_bill_content;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(getCurrentPage()));
        hashMap.put("type", VideoTypeBean.video_type_point);
        Unit unit = Unit.INSTANCE;
        return C0917a.m222f(c0917a, "user/accountLogs", BillBean.class, hashMap, new Function1<List<? extends BillBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.BillListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends BillBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends BillBean> list) {
                BillListFragment.this.didRequestComplete(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.wallet.BillListFragment$request$3
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
                BillListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull BillBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String note = item.getNote();
        if (note == null) {
            note = "";
        }
        helper.m3919i(R.id.tvType, note);
        helper.m3919i(R.id.tvState, item.getType());
        helper.m3919i(R.id.tvTime, String.valueOf(item.getTime_label()));
        helper.m3919i(R.id.tvNum, Intrinsics.areEqual(item.getType(), "充值") ? Intrinsics.stringPlus(BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX, item.getAmount()) : item.getAmount());
        String amount = item.getAmount();
        if (StringsKt__StringsKt.contains$default((CharSequence) (amount != null ? amount : ""), (CharSequence) "-", false, 2, (Object) null)) {
            helper.m3921k(R.id.tvNum, R.color.main_b3e60217);
        } else {
            helper.m3921k(R.id.tvNum, R.color.main_60c926);
        }
    }
}
