package com.jbzd.media.movecartoons.p396ui.index.post;

import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.PostListBean;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment;
import com.qnmd.adnnm.da0yzo.R;
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
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\t\u0018\u0000 \u001b2\u00020\u0001:\u0001\u001bB\u0007¢\u0006\u0004\b\u001a\u0010\u0007J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\u0007J\u000f\u0010\t\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\t\u0010\u0004J\u001f\u0010\u000e\u001a\u00020\u00052\u0006\u0010\u000b\u001a\u00020\n2\u0006\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u0011\u0010\u0011\u001a\u0004\u0018\u00010\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012R\"\u0010\u0014\u001a\u00020\u00138\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0014\u0010\u0015\u001a\u0004\b\u0016\u0010\u0017\"\u0004\b\u0018\u0010\u0019¨\u0006\u001c"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonPostListFragment;", "", "getLayout", "()I", "", "initViews", "()V", "onResume", "getItemLayoutId", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/PostListBean;", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostListBean;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "", "refresh", "Z", "getRefresh", "()Z", "setRefresh", "(Z)V", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostHomeBottomFragment extends CommonPostListFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private boolean refresh = true;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment$Companion;", "", "", "home_id", "Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/post/PostHomeBottomFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final PostHomeBottomFragment newInstance(@NotNull String home_id) {
            Intrinsics.checkNotNullParameter(home_id, "home_id");
            PostHomeBottomFragment postHomeBottomFragment = new PostHomeBottomFragment();
            postHomeBottomFragment.setUserId(home_id);
            postHomeBottomFragment.setIntoType("userPostHomePage");
            return postHomeBottomFragment;
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_posthome_postitem;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.list_frag;
    }

    public final boolean getRefresh() {
        return this.refresh;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        request();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        this.refresh = true;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        HashMap hashMap = new HashMap();
        hashMap.put("home_id", getUserId());
        hashMap.put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, "post/search", PostListBean.class, hashMap, new Function1<List<? extends PostListBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeBottomFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends PostListBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends PostListBean> list) {
                if (list == null) {
                    return;
                }
                PostHomeBottomFragment.this.didRequestComplete(CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.post.PostHomeBottomFragment$request$3
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

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonPostListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull PostListBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        super.bindItem(helper, item);
        helper.m3916f(R.id.ll_posthome_usertop, false);
        helper.m3916f(R.id.itv_postuser_follow, false);
    }
}
