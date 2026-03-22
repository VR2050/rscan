package com.jbzd.media.movecartoons.p396ui.search.child;

import android.os.Bundle;
import android.view.View;
import androidx.annotation.RequiresApi;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.event.EventUpdate;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.qnmd.adnnm.da0yzo.R;
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
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\u000b\n\u0002\b\t\u0018\u0000 '2\u00020\u0001:\u0001'B\u0007¢\u0006\u0004\b&\u0010\u0011J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\u0006\u001a\u00020\u00052\u0006\u0010\b\u001a\u00020\u0007H\u0017¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\u000e\u001a\u00020\t2\u0006\u0010\r\u001a\u00020\fH\u0007¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0010\u0010\u0011J\u000f\u0010\u0012\u001a\u00020\tH\u0016¢\u0006\u0004\b\u0012\u0010\u0011J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0017\u001a\u00020\u0016H\u0016¢\u0006\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001e\u001a\u00020\u00198F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001a\u0010\u001b\u001a\u0004\b\u001c\u0010\u001dR\"\u0010 \u001a\u00020\u001f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b \u0010!\u001a\u0004\b\"\u0010#\"\u0004\b$\u0010%¨\u0006("}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListLong;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListFragment;", "", "getLayout", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;", "data", "onUpdateSearch", "(Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;)V", "onStart", "()V", "onDestroy", "Landroid/view/View;", "getEmptyDataView", "()Landroid/view/View;", "", "getRequestUrl", "()Ljava/lang/String;", "Landroidx/coordinatorlayout/widget/CoordinatorLayout;", "layout_search_empty$delegate", "Lkotlin/Lazy;", "getLayout_search_empty", "()Landroidx/coordinatorlayout/widget/CoordinatorLayout;", "layout_search_empty", "", "showGuess", "Z", "getShowGuess", "()Z", "setShowGuess", "(Z)V", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchResultListLong extends CommonLongListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: layout_search_empty$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy layout_search_empty = LazyKt__LazyJVMKt.lazy(new Function0<CoordinatorLayout>() { // from class: com.jbzd.media.movecartoons.ui.search.child.SearchResultListLong$layout_search_empty$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final CoordinatorLayout invoke() {
            View view = SearchResultListLong.this.getView();
            CoordinatorLayout coordinatorLayout = view == null ? null : (CoordinatorLayout) view.findViewById(R.id.layout_search_empty);
            Intrinsics.checkNotNull(coordinatorLayout);
            return coordinatorLayout;
        }
    });
    private boolean showGuess;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJA\u0010\t\u001a\u00020\b2(\b\u0002\u0010\u0005\u001a\"\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u00042\b\b\u0002\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListLong$Companion;", "", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "map", "", "isCartoon", "Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListLong;", "newInstance", "(Ljava/util/HashMap;Z)Lcom/jbzd/media/movecartoons/ui/search/child/SearchResultListLong;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ SearchResultListLong newInstance$default(Companion companion, HashMap hashMap, boolean z, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            if ((i2 & 2) != 0) {
                z = false;
            }
            return companion.newInstance(hashMap, z);
        }

        @NotNull
        public final SearchResultListLong newInstance(@Nullable HashMap<String, String> map, boolean isCartoon) {
            SearchResultListLong searchResultListLong = new SearchResultListLong();
            Bundle bundle = new Bundle();
            bundle.putSerializable("params_map", map);
            searchResultListLong.setISCARTOON(isCartoon);
            Unit unit = Unit.INSTANCE;
            searchResultListLong.setArguments(bundle);
            return searchResultListLong;
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
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

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.list_search_frag;
    }

    @NotNull
    public final CoordinatorLayout getLayout_search_empty() {
        return (CoordinatorLayout) this.layout_search_empty.getValue();
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment
    @NotNull
    public String getRequestUrl() {
        return super.getRequestUrl();
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
    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    @RequiresApi(23)
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        super.bindItem(helper, item);
    }
}
