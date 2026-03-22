package com.jbzd.media.movecartoons.p396ui.search.child;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.annotation.RequiresApi;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.UserInfoBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.p396ui.dialog.RestrictedDialog;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import me.jingbin.library.decoration.GridSpaceItemDecoration;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Z\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u000f\b\u0016\u0018\u0000 02\u00020\u0001:\u00010B\u0007¢\u0006\u0004\b.\u0010/J+\u0010\u0005\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030\u0002j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`\u0004H\u0016¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\b\u0010\tJ\u001f\u0010\u000f\u001a\u00020\u000e2\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\r\u001a\u00020\fH\u0017¢\u0006\u0004\b\u000f\u0010\u0010J3\u0010\u0016\u001a\u00020\u000e2\u0012\u0010\u0012\u001a\u000e\u0012\u0004\u0012\u00020\f\u0012\u0004\u0012\u00020\n0\u00112\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0015\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u000f\u0010\u0019\u001a\u00020\u0018H\u0017¢\u0006\u0004\b\u0019\u0010\u001aJ\u0011\u0010\u001c\u001a\u0004\u0018\u00010\u001bH\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\u000f\u0010\u001e\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\u0007H\u0016¢\u0006\u0004\b \u0010\tJ\u000f\u0010!\u001a\u00020\u0007H\u0016¢\u0006\u0004\b!\u0010\tR\"\u0010#\u001a\u00020\"8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&\"\u0004\b'\u0010(R\"\u0010)\u001a\u00020\u00038\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b)\u0010*\u001a\u0004\b+\u0010\u001f\"\u0004\b,\u0010-¨\u00061"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/BaseCommonVideoListFragment;", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "getRequestBody", "()Ljava/util/HashMap;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getEmptyTips", "()Ljava/lang/String;", "getLeftPadding", "getRightPadding", "", "ISCARTOON", "Z", "getISCARTOON", "()Z", "setISCARTOON", "(Z)V", "style", "Ljava/lang/String;", "getStyle", "setStyle", "(Ljava/lang/String;)V", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public class CommonLongListFragment extends BaseCommonVideoListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private boolean ISCARTOON;

    @NotNull
    private String style = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ7\u0010\u0007\u001a\u00020\u00062(\b\u0002\u0010\u0005\u001a\"\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListFragment$Companion;", "", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "map", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListFragment;", "newInstance", "(Ljava/util/HashMap;)Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ CommonLongListFragment newInstance$default(Companion companion, HashMap hashMap, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            return companion.newInstance(hashMap);
        }

        @NotNull
        public final CommonLongListFragment newInstance(@Nullable HashMap<String, String> map) {
            CommonLongListFragment commonLongListFragment = new CommonLongListFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("params_map", map);
            Unit unit = Unit.INSTANCE;
            commonLongListFragment.setArguments(bundle);
            return commonLongListFragment;
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

    public final boolean getISCARTOON() {
        return this.ISCARTOON;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        if (!getRequestBody().containsKey("style")) {
            return new GridSpaceItemDecoration(C2354n.m2425R(getContext(), 5.0f));
        }
        this.style = String.valueOf(getRequestBody().get("style"));
        return new GridSpaceItemDecoration(C2354n.m2425R(getContext(), 5.0f));
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        if (getRequestBody().containsKey("style")) {
            String valueOf = String.valueOf(getRequestBody().get("style"));
            this.style = valueOf;
            if (Intrinsics.areEqual(valueOf, HomeDataHelper.type_tag) || Intrinsics.areEqual(this.style, "5") || Intrinsics.areEqual(this.style, MainMenusBean.TYPE_APPS_CENTER)) {
                return R.layout.video_short_item1;
            }
        }
        return R.layout.video_long_item1;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @SuppressLint({"SuspiciousIndentation"})
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        if (!getRequestBody().containsKey("style")) {
            return new GridLayoutManager(requireContext(), 2);
        }
        String valueOf = String.valueOf(getRequestBody().get("style"));
        this.style = valueOf;
        return (Intrinsics.areEqual(valueOf, HomeDataHelper.type_tag) || Intrinsics.areEqual(this.style, "5") || Intrinsics.areEqual(this.style, MainMenusBean.TYPE_APPS_CENTER)) ? new GridLayoutManager(requireContext(), 3) : new GridLayoutManager(requireContext(), 2);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return C2354n.m2425R(requireContext(), 1.0f);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public HashMap<String, String> getRequestBody() {
        Bundle arguments = getArguments();
        HashMap<String, String> hashMap = (HashMap) (arguments == null ? null : arguments.getSerializable("params_map"));
        return hashMap == null ? createEmptyRequestBody() : hashMap;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return C2354n.m2425R(requireContext(), 1.0f);
    }

    @NotNull
    public final String getStyle() {
        return this.style;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<VideoItemBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Integer num;
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        VideoItemBean videoItemBean = adapter.getData().get(position);
        if (videoItemBean.type.equals("ad")) {
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
            new RestrictedDialog(null, num3.intValue(), 0, null, null, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonLongListFragment$onItemClick$1
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
                    Context requireContext2 = CommonLongListFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    companion2.start(requireContext2);
                }
            }, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonLongListFragment$onItemClick$2
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
                    Context requireContext2 = CommonLongListFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    companion2.start(requireContext2);
                }
            }, 29, null).show(getChildFragmentManager(), "RestrictedDialog");
            return;
        }
        FragmentActivity activity = getActivity();
        if (activity instanceof MovieDetailsActivity) {
            ((MovieDetailsActivity) activity).getViewModel().loadMovie(videoItemBean.f10000id, "");
            return;
        }
        MovieDetailsActivity.Companion companion2 = MovieDetailsActivity.INSTANCE;
        Context requireContext2 = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
        companion2.start(requireContext2, videoItemBean.f10000id);
    }

    public final void setISCARTOON(boolean z) {
        this.ISCARTOON = z;
    }

    public final void setStyle(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.style = str;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @RequiresApi(23)
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsgNew(requireContext, helper, item, (r23 & 8) != 0, (r23 & 16) != 0, (r23 & 32) != 0, (r23 & 64) != 0, (r23 & 128) != 0 ? false : false, (r23 & 256) != 0, (r23 & 512) != 0 ? false : false);
    }
}
