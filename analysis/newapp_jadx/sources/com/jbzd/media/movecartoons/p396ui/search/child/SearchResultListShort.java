package com.jbzd.media.movecartoons.p396ui.search.child;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.event.EventUpdate;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
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
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000T\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\t\u0018\u0000 ,2\u00020\u0001:\u0001,B\u0007¢\u0006\u0004\b+\u0010\u000eJ\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\tH\u0007¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u000f\u0010\u000eJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u0011\u0010\u0017\u001a\u0004\u0018\u00010\u0016H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u000f\u0010\u001a\u001a\u00020\u0019H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u000f\u0010\u001c\u001a\u00020\u0019H\u0016¢\u0006\u0004\b\u001c\u0010\u001bJ\u000f\u0010\u001d\u001a\u00020\u0019H\u0016¢\u0006\u0004\b\u001d\u0010\u001bR\u001d\u0010#\u001a\u00020\u001e8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"R\"\u0010%\u001a\u00020$8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(\"\u0004\b)\u0010*¨\u0006-"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListShort;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonShortListFragment;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;", "data", "onUpdateSearch", "(Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;)V", "onStart", "()V", "onDestroy", "Landroid/view/View;", "getEmptyDataView", "()Landroid/view/View;", "", "getRequestUrl", "()Ljava/lang/String;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "", "getLeftPadding", "()I", "getRightPadding", "getLayout", "Landroidx/coordinatorlayout/widget/CoordinatorLayout;", "layout_search_empty$delegate", "Lkotlin/Lazy;", "getLayout_search_empty", "()Landroidx/coordinatorlayout/widget/CoordinatorLayout;", "layout_search_empty", "", "showGuess", "Z", "getShowGuess", "()Z", "setShowGuess", "(Z)V", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchResultListShort extends CommonShortListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: layout_search_empty$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_search_empty = LazyKt__LazyJVMKt.lazy(new Function0<CoordinatorLayout>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchResultListShort$layout_search_empty$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CoordinatorLayout invoke() {
            View view = SearchResultListShort.this.getView();
            CoordinatorLayout coordinatorLayout = view == null ? null : (CoordinatorLayout) view.findViewById(R.id.layout_search_empty);
            Intrinsics.checkNotNull(coordinatorLayout);
            return coordinatorLayout;
        }
    });
    private boolean showGuess;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\f\u0010\rJK\u0010\n\u001a\u00020\t2(\b\u0002\u0010\u0005\u001a\"\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u00042\b\b\u0002\u0010\u0007\u001a\u00020\u00062\b\b\u0002\u0010\b\u001a\u00020\u0006¢\u0006\u0004\b\n\u0010\u000b¨\u0006\u000e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListShort$Companion;", "", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "map", "", "showGuess", "searchGuess", "Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListShort;", "newInstance", "(Ljava/util/HashMap;ZZ)Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListShort;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ SearchResultListShort newInstance$default(Companion companion, HashMap hashMap, boolean z, boolean z2, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            if ((i2 & 2) != 0) {
                z = false;
            }
            if ((i2 & 4) != 0) {
                z2 = false;
            }
            return companion.newInstance(hashMap, z, z2);
        }

        @NotNull
        public final SearchResultListShort newInstance(@Nullable HashMap<String, String> map, boolean showGuess, boolean searchGuess) {
            SearchResultListShort searchResultListShort = new SearchResultListShort();
            Bundle bundle = new Bundle();
            bundle.putSerializable("params_map", map);
            bundle.putBoolean("showGuess", showGuess);
            bundle.putBoolean("searchGuess", searchGuess);
            Unit unit = Unit.INSTANCE;
            searchResultListShort.setArguments(bundle);
            return searchResultListShort;
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public View getEmptyDataView() {
        View emptyDataView = super.getEmptyDataView();
        if (requireArguments().getBoolean("showGuess") && !this.showGuess) {
            requireActivity().findViewById(R.id.rootViewBg).setVisibility(8);
            getLayout_search_empty().setVisibility(0);
            this.showGuess = true;
            setCurrentPage(0);
            loadMore();
        }
        return emptyDataView;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
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

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return C2354n.m2425R(requireContext(), 10.0f);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public String getRequestUrl() {
        if (!this.showGuess) {
            return super.getRequestUrl();
        }
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.f1059h = false;
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 != null) {
            loadMoreModule2.f1058g = false;
        }
        C1318f loadMoreModule3 = getAdapter().getLoadMoreModule();
        if (loadMoreModule3 != null) {
            loadMoreModule3.m334k(false);
        }
        C1318f loadMoreModule4 = getAdapter().getLoadMoreModule();
        if (loadMoreModule4 != null) {
            loadMoreModule4.m330f();
        }
        C1318f loadMoreModule5 = getAdapter().getLoadMoreModule();
        if (loadMoreModule5 == null) {
            return "video/guess";
        }
        loadMoreModule5.m331g(true);
        return "video/guess";
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return C2354n.m2425R(requireContext(), 10.0f);
    }

    public final boolean getShowGuess() {
        return this.showGuess;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        C4909c.m5569b().m5580m(this);
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        if (C4909c.m5569b().m5573f(this)) {
            return;
        }
        C4909c.m5569b().m5578k(this);
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onUpdateSearch(@NotNull EventUpdate data) {
        Intrinsics.checkNotNullParameter(data, "data");
        if (data.getOrderBy() != null) {
            updateOrderBy(data.getOrderBy());
        } else if (data.getVideoType() != null) {
            updateVideoType(data.getVideoType());
        }
    }

    public final void setShowGuess(boolean z) {
        this.showGuess = z;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonShortListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : true, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
    }
}
