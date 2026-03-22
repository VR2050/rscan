package com.jbzd.media.movecartoons.p396ui.search.child;

import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import androidx.annotation.RequiresApi;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.p396ui.dialog.RestrictedDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\b\b\u0016\u0018\u0000 $2\u00020\u0001:\u0001$B\u0007¢\u0006\u0004\b\"\u0010#J+\u0010\u0005\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0002j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u001f\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\r\u001a\u00020\fH\u0017¢\u0006\u0004\b\u000f\u0010\u0010J3\u0010\u0016\u001a\u00020\u000e2\u0012\u0010\u0012\u001a\u000e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\n0\u00112\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0015\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u000f\u0010\u0019\u001a\u00020\u0018H\u0016¢\u0006\u0004\b\u0019\u0010\u001aJ\u000f\u0010\u001b\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001b\u0010\u001cJ\u0011\u0010\u001e\u001a\u0004\u0018\u00010\u001dH\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\u0007H\u0016¢\u0006\u0004\b \u0010\tJ\u000f\u0010!\u001a\u00020\u0007H\u0016¢\u0006\u0004\b!\u0010\t¨\u0006%"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonShortListFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/BaseCommonVideoListFragment;", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "getRequestBody", "()Ljava/util/HashMap;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getEmptyTips", "()Ljava/lang/String;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getLeftPadding", "getRightPadding", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public class CommonShortListFragment extends BaseCommonVideoListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ7\u0010\u0007\u001a\u00020\u00062(\b\u0002\u0010\u0005\u001a\"\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonShortListFragment$Companion;", "", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "map", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonShortListFragment;", "newInstance", "(Ljava/util/HashMap;)Lcom/jbzd/media/movecartoons/ui/search/child/CommonShortListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ CommonShortListFragment newInstance$default(Companion companion, HashMap hashMap, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            return companion.newInstance(hashMap);
        }

        @NotNull
        public final CommonShortListFragment newInstance(@Nullable HashMap<String, String> map) {
            CommonShortListFragment commonShortListFragment = new CommonShortListFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("params_map", map);
            Unit unit = Unit.INSTANCE;
            commonShortListFragment.setArguments(bundle);
            return commonShortListFragment;
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public String getEmptyTips() {
        return "当前页面暂无内容";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
        c4053a.m4576a(R.color.transparent);
        c4053a.f10336d = C2354n.m2437V(getContext(), 5.0d);
        c4053a.f10337e = C2354n.m2437V(getContext(), 8.0d);
        c4053a.f10339g = false;
        c4053a.f10340h = false;
        c4053a.f10338f = false;
        return new GridItemDecoration(c4053a);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.video_short_item1;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(getContext(), 3);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return C2354n.m2425R(requireContext(), 10.0f);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public HashMap<String, String> getRequestBody() {
        Bundle arguments = getArguments();
        HashMap<String, String> hashMap = (HashMap) (arguments == null ? null : arguments.getSerializable("params_map"));
        if (hashMap == null) {
            hashMap = createEmptyRequestBody();
        }
        String str = hashMap.get("canvas");
        if (str == null || str.length() == 0) {
            hashMap.put("canvas", "short");
        }
        return hashMap;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return C2354n.m2425R(requireContext(), 10.0f);
    }

    /* JADX WARN: Multi-variable type inference failed */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<VideoItemBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Integer num;
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        VideoItemBean videoItemBean = adapter.getData().get(position);
        if (videoItemBean.getIsAd()) {
            MineViewModel.Companion companion = MineViewModel.INSTANCE;
            String str = videoItemBean.f10000id;
            Intrinsics.checkNotNullExpressionValue(str, "item.id");
            String str2 = videoItemBean.name;
            Intrinsics.checkNotNullExpressionValue(str2, "item.name");
            companion.systemTrack("ad", str, str2);
            C0840d.a aVar = C0840d.f235a;
            Context requireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            String str3 = videoItemBean.link;
            Intrinsics.checkNotNullExpressionValue(str3, "item.link");
            aVar.m175a(requireContext, str3);
            return;
        }
        Integer num2 = videoItemBean.watch_limit;
        Intrinsics.checkNotNullExpressionValue(num2, "item.watch_limit");
        int intValue = num2.intValue();
        MyApp myApp = MyApp.f9891f;
        UserInfoBean userInfoBean = MyApp.f9892g;
        int i2 = 0;
        if (userInfoBean != null && (num = userInfoBean.total_order) != null) {
            i2 = num.intValue();
        }
        if (intValue > i2) {
            Integer num3 = videoItemBean.watch_limit;
            Intrinsics.checkNotNullExpressionValue(num3, "item.watch_limit");
            new RestrictedDialog(null, num3.intValue(), 0, null, null, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonShortListFragment$onItemClick$1
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    BuyActivity.Companion companion2 = BuyActivity.Companion;
                    Context requireContext2 = CommonShortListFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    companion2.start(requireContext2);
                }
            }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonShortListFragment$onItemClick$2
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2() {
                    RechargeActivity.Companion companion2 = RechargeActivity.Companion;
                    Context requireContext2 = CommonShortListFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    companion2.start(requireContext2);
                }
            }, 29, null).show(getChildFragmentManager(), "RestrictedDialog");
            return;
        }
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(videoItemBean.realPage));
        HashMap<String, String> requestRoomParameter = getRequestRoomParameter();
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        for (Map.Entry<String, String> entry : requestRoomParameter.entrySet()) {
            if (!TextUtils.equals(entry.getKey(), "page")) {
                linkedHashMap.put(entry.getKey(), entry.getValue());
            }
        }
        for (Map.Entry entry2 : linkedHashMap.entrySet()) {
            hashMap.put(entry2.getKey(), entry2.getValue());
        }
        FragmentActivity activity = getActivity();
        if (activity instanceof PlayListActivity) {
            if (Intrinsics.areEqual(getMDefaultCanvas(), "image")) {
                ((PlayListActivity) activity).refreshPlayList(videoItemBean.f10000id, hashMap, "photoAlbum/list");
                return;
            } else {
                PlayListActivity.refreshPlayList$default((PlayListActivity) activity, videoItemBean.f10000id, hashMap, null, 4, null);
                return;
            }
        }
        if (Intrinsics.areEqual(getMDefaultCanvas(), "image")) {
            PlayListActivity.Companion companion2 = PlayListActivity.INSTANCE;
            Context requireContext2 = requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
            companion2.start(requireContext2, (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : "photoAlbum/list", (r13 & 16) != 0 ? false : false);
            return;
        }
        PlayListActivity.Companion companion3 = PlayListActivity.INSTANCE;
        Context requireContext3 = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext3, "requireContext()");
        companion3.start(requireContext3, (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @RequiresApi(23)
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
    }
}
