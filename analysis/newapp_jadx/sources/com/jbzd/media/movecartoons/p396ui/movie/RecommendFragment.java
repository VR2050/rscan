package com.jbzd.media.movecartoons.p396ui.movie;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0005\n\u0002\u0010!\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 42\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00014B\u0007¢\u0006\u0004\b3\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u001f\u0010\u000f\u001a\u00020\u00062\u0006\u0010\r\u001a\u00020\f2\u0006\u0010\u000e\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u0011\u0010\u0012\u001a\u0004\u0018\u00010\u0011H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u0011\u0010\u0015\u001a\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J3\u0010\u001c\u001a\u00020\u00062\u0012\u0010\u0018\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\f0\u00172\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u001b\u001a\u00020\tH\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\u000f\u0010\u001f\u001a\u00020\u001eH\u0016¢\u0006\u0004\b\u001f\u0010 J\u000f\u0010!\u001a\u00020\u001eH\u0016¢\u0006\u0004\b!\u0010 R\u001d\u0010'\u001a\u00020\"8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&R\u001f\u0010)\u001a\b\u0012\u0004\u0012\u00020\u00020(8\u0006@\u0006¢\u0006\f\n\u0004\b)\u0010*\u001a\u0004\b+\u0010,R-\u00102\u001a\u0012\u0012\u0004\u0012\u00020\u00020-j\b\u0012\u0004\u0012\u00020\u0002`.8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b/\u0010$\u001a\u0004\b0\u00101¨\u00065"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/RecommendFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "", "onResume", "()V", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Lc/a/d1;", "request", "()Lc/a/d1;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "", "getRefreshEnable", "()Z", "getLoadMoreEnable", "", "mVideoId$delegate", "Lkotlin/Lazy;", "getMVideoId", "()Ljava/lang/String;", "mVideoId", "", "items", "Ljava/util/List;", "getItems", "()Ljava/util/List;", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "mVideoItems$delegate", "getMVideoItems", "()Ljava/util/ArrayList;", "mVideoItems", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RecommendFragment extends BaseListFragment<VideoItemBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String key_video_id = "key_video_id";

    @NotNull
    public static final String key_video_item = "video_item";

    /* renamed from: mVideoItems$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mVideoItems = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<VideoItemBean>>() { // from class: com.jbzd.media.movecartoons.ui.movie.RecommendFragment$mVideoItems$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<VideoItemBean> invoke() {
            Bundle arguments = RecommendFragment.this.getArguments();
            Serializable serializable = arguments == null ? null : arguments.getSerializable(RecommendFragment.key_video_item);
            Objects.requireNonNull(serializable, "null cannot be cast to non-null type java.util.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean>{ kotlin.collections.TypeAliasesKt.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean> }");
            return (ArrayList) serializable;
        }
    });

    /* renamed from: mVideoId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mVideoId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.movie.RecommendFragment$mVideoId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            Bundle arguments = RecommendFragment.this.getArguments();
            String string = arguments == null ? null : arguments.getString(RecommendFragment.key_video_id);
            Objects.requireNonNull(string, "null cannot be cast to non-null type kotlin.String");
            return string;
        }
    });

    @NotNull
    private final List<VideoItemBean> items = new ArrayList();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ%\u0010\b\u001a\u00020\u00072\u000e\u0010\u0004\u001a\n\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u00022\u0006\u0010\u0006\u001a\u00020\u0005¢\u0006\u0004\b\b\u0010\tR\u0016\u0010\n\u001a\u00020\u00058\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\n\u0010\u000bR\u0016\u0010\f\u001a\u00020\u00058\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\f\u0010\u000b¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/RecommendFragment$Companion;", "", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "videoList", "", "id", "Lcom/jbzd/media/movecartoons/ui/movie/RecommendFragment;", "newInstance", "(Ljava/util/List;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/movie/RecommendFragment;", RecommendFragment.key_video_id, "Ljava/lang/String;", "key_video_item", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final RecommendFragment newInstance(@Nullable List<? extends VideoItemBean> videoList, @NotNull String id) {
            Intrinsics.checkNotNullParameter(id, "id");
            RecommendFragment recommendFragment = new RecommendFragment();
            Bundle bundle = new Bundle();
            Objects.requireNonNull(videoList, "null cannot be cast to non-null type java.io.Serializable");
            bundle.putSerializable(RecommendFragment.key_video_item, (Serializable) videoList);
            bundle.putString(RecommendFragment.key_video_id, id);
            Unit unit = Unit.INSTANCE;
            recommendFragment.setArguments(bundle);
            return recommendFragment;
        }
    }

    private final String getMVideoId() {
        return (String) this.mVideoId.getValue();
    }

    private final ArrayList<VideoItemBean> getMVideoItems() {
        return (ArrayList) this.mVideoItems.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
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
        return R.layout.video_long_item1;
    }

    @NotNull
    public final List<VideoItemBean> getItems() {
        return this.items;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(requireContext(), 2);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getLoadMoreEnable() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getRefreshEnable() {
        return false;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<VideoItemBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        VideoItemBean videoItemBean = adapter.getData().get(position);
        MovieDetailsActivity.Companion companion = MovieDetailsActivity.INSTANCE;
        FragmentActivity requireActivity = requireActivity();
        Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
        companion.start(requireActivity, videoItemBean.f10000id);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        didRequestComplete(getMVideoItems());
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        return null;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsgNew(requireContext, helper, item, (r23 & 8) != 0, (r23 & 16) != 0 ? true : true, (r23 & 32) != 0 ? true : true, (r23 & 64) != 0 ? true : true, (r23 & 128) != 0 ? false : false, (r23 & 256) != 0, (r23 & 512) != 0 ? false : false);
        getItems().add(item);
        String str = item.name;
        Intrinsics.checkNotNullExpressionValue(str, "item.name");
        helper.m3919i(R.id.tv_name, StringsKt__StringsKt.trim((CharSequence) str).toString());
    }
}
