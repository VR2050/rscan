package com.jbzd.media.movecartoons.p396ui.search.child;

import android.os.Bundle;
import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\t\u0018\u0000 \u001f2\u00020\u0001:\u0001\u001fB\u0007¢\u0006\u0004\b\u001d\u0010\u001eJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0011\u0010\u0010\u001a\u0004\u0018\u00010\u000fH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0013\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u0015\u0010\u0014J\u000f\u0010\u0016\u001a\u00020\u0012H\u0016¢\u0006\u0004\b\u0016\u0010\u0014R\u001d\u0010\u001c\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001b¨\u0006 "}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchPostResultFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostListBean;)V", "Landroid/view/View;", "getEmptyDataView", "()Landroid/view/View;", "", "getRequestUrl", "()Ljava/lang/String;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "", "getLeftPadding", "()I", "getRightPadding", "getLayout", "Landroidx/coordinatorlayout/widget/CoordinatorLayout;", "layout_search_empty$delegate", "Lkotlin/Lazy;", "getLayout_search_empty", "()Landroidx/coordinatorlayout/widget/CoordinatorLayout;", "layout_search_empty", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchPostResultFragment extends CommonPostListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: layout_search_empty$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_search_empty = LazyKt__LazyJVMKt.lazy(new Function0<CoordinatorLayout>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchPostResultFragment$layout_search_empty$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CoordinatorLayout invoke() {
            View view = SearchPostResultFragment.this.getView();
            CoordinatorLayout coordinatorLayout = view == null ? null : (CoordinatorLayout) view.findViewById(R.id.layout_search_empty);
            Intrinsics.checkNotNull(coordinatorLayout);
            return coordinatorLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ7\u0010\u0007\u001a\u00020\u00062(\b\u0002\u0010\u0005\u001a\"\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchPostResultFragment$Companion;", "", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "map", "Lcom/jbzd/media/movecartoons/ui/search/child/SearchPostResultFragment;", "newInstance", "(Ljava/util/HashMap;)Lcom/jbzd/media/movecartoons/ui/search/child/SearchPostResultFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ SearchPostResultFragment newInstance$default(Companion companion, HashMap hashMap, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            return companion.newInstance(hashMap);
        }

        @NotNull
        public final SearchPostResultFragment newInstance(@Nullable HashMap<String, String> map) {
            SearchPostResultFragment searchPostResultFragment = new SearchPostResultFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("params_map", map);
            Unit unit = Unit.INSTANCE;
            searchPostResultFragment.setArguments(bundle);
            return searchPostResultFragment;
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public View getEmptyDataView() {
        View emptyDataView = super.getEmptyDataView();
        if (requireArguments().getBoolean("showGuess")) {
            requireActivity().findViewById(R.id.rootViewBg).setVisibility(8);
            getLayout_search_empty().setVisibility(0);
            setCurrentPage(0);
            loadMore();
        }
        return emptyDataView;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
        c4053a.m4576a(R.color.transparent);
        c4053a.f10336d = C2354n.m2437V(getContext(), 5.0d);
        c4053a.f10337e = C2354n.m2437V(getContext(), 4.0d);
        c4053a.f10339g = false;
        c4053a.f10340h = false;
        c4053a.f10338f = false;
        return new GridItemDecoration(c4053a);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.list_search_frag;
    }

    @NotNull
    public final CoordinatorLayout getLayout_search_empty() {
        return (CoordinatorLayout) this.layout_search_empty.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return C2354n.m2425R(requireContext(), 10.0f);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment
    @NotNull
    public String getRequestUrl() {
        return super.getRequestUrl();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return C2354n.m2425R(requireContext(), 10.0f);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull PostListBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        super.bindItem(helper, item);
    }
}
