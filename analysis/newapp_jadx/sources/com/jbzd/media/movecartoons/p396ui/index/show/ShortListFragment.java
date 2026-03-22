package com.jbzd.media.movecartoons.p396ui.index.show;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000d\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\n\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 92\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00019B\u0007¢\u0006\u0004\b7\u00108J\u0017\u0010\u0006\u001a\u00020\u00052\b\u0010\u0004\u001a\u0004\u0018\u00010\u0003¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\t\u001a\u00020\u00052\b\u0010\b\u001a\u0004\u0018\u00010\u0003¢\u0006\u0004\b\t\u0010\u0007J!\u0010\f\u001a\u00020\u00052\b\u0010\n\u001a\u0004\u0018\u00010\u00032\b\u0010\u000b\u001a\u0004\u0018\u00010\u0003¢\u0006\u0004\b\f\u0010\rJ\u0017\u0010\u000f\u001a\u00020\u00052\b\u0010\u000e\u001a\u0004\u0018\u00010\u0003¢\u0006\u0004\b\u000f\u0010\u0007J\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u001f\u0010\u0016\u001a\u00020\u00052\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0015\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J3\u0010\u001d\u001a\u00020\u00052\u0012\u0010\u0019\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00130\u00182\u0006\u0010\u001b\u001a\u00020\u001a2\u0006\u0010\u001c\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u001d\u0010\u001eJ\u0011\u0010 \u001a\u0004\u0018\u00010\u001fH\u0016¢\u0006\u0004\b \u0010!J\u000f\u0010#\u001a\u00020\"H\u0016¢\u0006\u0004\b#\u0010$J\u000f\u0010%\u001a\u00020\u0010H\u0016¢\u0006\u0004\b%\u0010\u0012J\u000f\u0010&\u001a\u00020\u0010H\u0016¢\u0006\u0004\b&\u0010\u0012J\u000f\u0010'\u001a\u00020\u0010H\u0016¢\u0006\u0004\b'\u0010\u0012J\u0011\u0010)\u001a\u0004\u0018\u00010(H\u0016¢\u0006\u0004\b)\u0010*R9\u00101\u001a\u001e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u00030+j\u000e\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003`,8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010.\u001a\u0004\b/\u00100R\u001f\u00106\u001a\u0004\u0018\u0001028B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b3\u0010.\u001a\u0004\b4\u00105¨\u0006:"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/show/ShortListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "", "userIds", "", "updateUserIds", "(Ljava/lang/String;)V", "tagIds", "updateTags", "ids", "key", "updateIds", "(Ljava/lang/String;Ljava/lang/String;)V", "orderBy", "updateOrderBy", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLeftPadding", "getRightPadding", "getTopPadding", "Lc/a/d1;", "request", "()Lc/a/d1;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "body$delegate", "Lkotlin/Lazy;", "getBody", "()Ljava/util/HashMap;", "body", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean$delegate", "getMTabBean", "()Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "mTabBean", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ShortListFragment extends BaseListFragment<VideoItemBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String key_tab = "tab_bean";

    /* renamed from: mTabBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTabBean = LazyKt__LazyJVMKt.lazy(new Function0<MainMenusBean>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShortListFragment$mTabBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final MainMenusBean invoke() {
            Bundle arguments = ShortListFragment.this.getArguments();
            return (MainMenusBean) (arguments == null ? null : arguments.getSerializable("tab_bean"));
        }
    });

    /* renamed from: body$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy body = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShortListFragment$body$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            MainMenusBean mTabBean;
            String str;
            HashMap<String, String> hashMap = new HashMap<>();
            mTabBean = ShortListFragment.this.getMTabBean();
            String str2 = "";
            if (mTabBean != null && (str = mTabBean.f10030id) != null) {
                str2 = str;
            }
            hashMap.put("tab_id", str2);
            return hashMap;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\b\u001a\u00020\u00078\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\b\u0010\t¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/show/ShortListFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;", "tabBean", "Lcom/jbzd/media/movecartoons/ui/index/show/ShortListFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/system/MainMenusBean;)Lcom/jbzd/media/movecartoons/ui/index/show/ShortListFragment;", "", "key_tab", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ShortListFragment newInstance(@Nullable MainMenusBean tabBean) {
            ShortListFragment shortListFragment = new ShortListFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("tab_bean", tabBean);
            Unit unit = Unit.INSTANCE;
            shortListFragment.setArguments(bundle);
            return shortListFragment;
        }
    }

    private final HashMap<String, String> getBody() {
        return (HashMap) this.body.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MainMenusBean getMTabBean() {
        return (MainMenusBean) this.mTabBean.getValue();
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
        return R.layout.video_short_item_black;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(requireContext(), 2);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return C2354n.m2437V(getContext(), 12.0d);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return C2354n.m2437V(getContext(), 12.0d);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getTopPadding() {
        return C2354n.m2437V(getContext(), 3.0d);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<VideoItemBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        VideoItemBean videoItemBean = adapter.getData().get(position);
        if (videoItemBean.getIsAd()) {
            return;
        }
        HashMap hashMap = new HashMap();
        for (Map.Entry<String, String> entry : getBody().entrySet()) {
            hashMap.put(entry.getKey(), entry.getValue());
        }
        hashMap.put("page", String.valueOf(videoItemBean.realPage));
        hashMap.put("has_image", HomeDataHelper.INSTANCE.getRequestHasImage(true));
        PlayListActivity.Companion companion = PlayListActivity.INSTANCE;
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        companion.start(requireContext, (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        getBody().put("page", String.valueOf(getCurrentPage()));
        final int currentPage = getCurrentPage();
        return C0917a.m222f(C0917a.f372a, "video/shortList", VideoItemBean.class, getBody(), new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShortListFragment$request$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                if (list != null) {
                    int i2 = currentPage;
                    Iterator<T> it = list.iterator();
                    while (it.hasNext()) {
                        ((VideoItemBean) it.next()).realPage = i2;
                    }
                }
                ShortListFragment.this.didRequestComplete(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.show.ShortListFragment$request$2
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
                ShortListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    public final void updateIds(@Nullable String ids, @Nullable String key) {
        String str = getBody().get("tab_id");
        getBody().clear();
        HashMap<String, String> body = getBody();
        if (str == null) {
            str = "";
        }
        body.put("tab_id", str);
        if (!(key == null || key.length() == 0)) {
            HashMap<String, String> body2 = getBody();
            if (ids == null) {
                ids = "";
            }
            body2.put(key, ids);
        }
        reset();
    }

    public final void updateOrderBy(@Nullable String orderBy) {
        HashMap<String, String> body = getBody();
        if (orderBy == null) {
            orderBy = "";
        }
        body.put("order_by", orderBy);
        reset();
    }

    public final void updateTags(@Nullable String tagIds) {
        HashMap<String, String> body = getBody();
        if (tagIds == null) {
            tagIds = "";
        }
        body.put("tag_id", tagIds);
        reset();
    }

    public final void updateUserIds(@Nullable String userIds) {
        HashMap<String, String> body = getBody();
        if (userIds == null) {
            userIds = "";
        }
        body.put("user_id", userIds);
        reset();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
    }
}
