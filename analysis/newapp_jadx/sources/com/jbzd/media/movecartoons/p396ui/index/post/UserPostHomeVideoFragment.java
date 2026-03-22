package com.jbzd.media.movecartoons.p396ui.index.post;

import android.content.Context;
import android.view.View;
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
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\t\u0018\u0000 )2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001)B\u0007¢\u0006\u0004\b(\u0010\u000eJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u0011\u0010\u0007\u001a\u0004\u0018\u00010\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\fH\u0016¢\u0006\u0004\b\u000f\u0010\u000eJ\u000f\u0010\u0010\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0010\u0010\u000bJ\u001f\u0010\u0014\u001a\u00020\f2\u0006\u0010\u0012\u001a\u00020\u00112\u0006\u0010\u0013\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\fH\u0016¢\u0006\u0004\b\u0016\u0010\u000eJ3\u0010\u001c\u001a\u00020\f2\u0012\u0010\u0018\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00110\u00172\u0006\u0010\u001a\u001a\u00020\u00192\u0006\u0010\u001b\u001a\u00020\tH\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\u0011\u0010\u001f\u001a\u0004\u0018\u00010\u001eH\u0016¢\u0006\u0004\b\u001f\u0010 R\"\u0010\"\u001a\u00020!8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%\"\u0004\b&\u0010'¨\u0006*"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/UserPostHomeVideoFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "", "getLayout", "()I", "", "initViews", "()V", "onResume", "getItemLayoutId", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "registerItemChildEvent", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemChildClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "", "refresh", "Z", "getRefresh", "()Z", "setRefresh", "(Z)V", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class UserPostHomeVideoFragment extends BaseListFragment<VideoItemBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String userId = "";
    private boolean refresh = true;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\"\u0010\u0007\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0007\u0010\b\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\f¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/UserPostHomeVideoFragment$Companion;", "", "", "home_id", "Lcom/jbzd/media/movecartoons/ui/index/post/UserPostHomeVideoFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/post/UserPostHomeVideoFragment;", "userId", "Ljava/lang/String;", "getUserId", "()Ljava/lang/String;", "setUserId", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getUserId() {
            return UserPostHomeVideoFragment.userId;
        }

        @NotNull
        public final UserPostHomeVideoFragment newInstance(@NotNull String home_id) {
            Intrinsics.checkNotNullParameter(home_id, "home_id");
            UserPostHomeVideoFragment userPostHomeVideoFragment = new UserPostHomeVideoFragment();
            UserPostHomeVideoFragment.INSTANCE.setUserId(home_id);
            return userPostHomeVideoFragment;
        }

        public final void setUserId(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            UserPostHomeVideoFragment.userId = str;
        }
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
        c4053a.m4576a(R.color.transparent);
        c4053a.f10336d = C2354n.m2437V(getContext(), 8.0d);
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

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.list_frag;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(requireContext(), 2);
    }

    public final boolean getRefresh() {
        return this.refresh;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        request();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemChildClick(@NotNull BaseQuickAdapter<VideoItemBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemChildClick(adapter, view, position);
        MovieDetailsActivity.Companion companion = MovieDetailsActivity.INSTANCE;
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        companion.start(requireContext, adapter.getItem(position).f10000id);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        this.refresh = true;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        registerItemChildClick(R.id.ll_item_video);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        HashMap hashMap = new HashMap();
        hashMap.put("home_id", userId);
        hashMap.put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, "movie/search", VideoItemBean.class, hashMap, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.UserPostHomeVideoFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends VideoItemBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends VideoItemBean> list) {
                if (list == null) {
                    return;
                }
                UserPostHomeVideoFragment.this.didRequestComplete(CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.UserPostHomeVideoFragment$request$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    public final void setRefresh(boolean z) {
        this.refresh = z;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsgNew(requireContext, helper, item, (r23 & 8) != 0, (r23 & 16) != 0 ? true : true, (r23 & 32) != 0 ? true : true, (r23 & 64) != 0 ? true : true, (r23 & 128) != 0 ? false : false, (r23 & 256) != 0, (r23 & 512) != 0 ? false : false);
    }
}
