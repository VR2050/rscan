package com.jbzd.media.movecartoons.p396ui.search;

import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.event.EventUpdate;
import com.jbzd.media.movecartoons.bean.response.CheckBean;
import com.jbzd.media.movecartoons.bean.response.HomeVideoGroupBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.core.BaseMutiListFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.OptionPopup;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.search.ModuleDetailActivity;
import com.jbzd.media.movecartoons.p396ui.search.SearchResultGroupFragment;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationV;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000X\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\t\u0018\u0000 .2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001.B\u0007¢\u0006\u0004\b-\u0010 J\u001f\u0010\b\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\tJ\u001f\u0010\u000b\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\n\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001f\u0010\r\u001a\u00020\u00072\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\n\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\r\u0010\fJ\u0011\u0010\u000f\u001a\u0004\u0018\u00010\u000eH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0012\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u0011\u0010\u0015\u001a\u0004\u0018\u00010\u0014H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J\u001f\u0010\u0019\u001a\u00020\u00072\u0006\u0010\u0017\u001a\u00020\u00032\u0006\u0010\u0018\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0019\u0010\fJ/\u0010\u001d\u001a\"\u0012\u0004\u0012\u00020\u001b\u0012\u0004\u0012\u00020\u001b\u0018\u00010\u001aj\u0010\u0012\u0004\u0012\u00020\u001b\u0012\u0004\u0012\u00020\u001b\u0018\u0001`\u001cH\u0016¢\u0006\u0004\b\u001d\u0010\u001eJ\u000f\u0010\u001f\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\u001f\u0010 J\u000f\u0010!\u001a\u00020\u0007H\u0016¢\u0006\u0004\b!\u0010 J\u0017\u0010$\u001a\u00020\u00072\u0006\u0010#\u001a\u00020\"H\u0007¢\u0006\u0004\b$\u0010%R2\u0010'\u001a\u001e\u0012\u0004\u0012\u00020&\u0012\u0004\u0012\u00020&0\u001aj\u000e\u0012\u0004\u0012\u00020&\u0012\u0004\u0012\u00020&`\u001c8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\b'\u0010(R\u0016\u0010)\u001a\u00020&8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b)\u0010*R\u0016\u0010+\u001a\u00020&8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b+\u0010*R\u0016\u0010,\u001a\u00020&8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b,\u0010*¨\u0006/"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/SearchResultGroupFragment;", "Lcom/jbzd/media/movecartoons/core/BaseMutiListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/HomeVideoGroupBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "outHelper", "Landroid/widget/LinearLayout;", "recyclerView", "", "setFrontendPadding", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Landroid/widget/LinearLayout;)V", "outItem", "showCollectionLong", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HomeVideoGroupBean;)V", "showCollectionShort", "Lc/a/d1;", "request", "()Lc/a/d1;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "helper", "item", "bindItem", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "getAllItemType", "()Ljava/util/HashMap;", "onStart", "()V", "onDestroy", "Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;", "search", "onUpdateSearch", "(Lcom/jbzd/media/movecartoons/bean/event/EventUpdate;)V", "", "requestRoomParameter", "Ljava/util/HashMap;", "mOrderBy", "Ljava/lang/String;", "mCurVideoType", "mKeywords", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchResultGroupFragment extends BaseMutiListFragment<HomeVideoGroupBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private String mCurVideoType;
    private String mKeywords;
    private String mOrderBy;

    @NotNull
    private final HashMap<String, String> requestRoomParameter = new HashMap<>();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0018\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ'\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0004\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0002¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/SearchResultGroupFragment$Companion;", "", "", "curOrderBy", "videoType", "keywords", "Lcom/jbzd/media/movecartoons/ui/search/SearchResultGroupFragment;", "newInstance", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/search/SearchResultGroupFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ SearchResultGroupFragment newInstance$default(Companion companion, String str, String str2, String str3, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                str2 = "";
            }
            return companion.newInstance(str, str2, str3);
        }

        @NotNull
        public final SearchResultGroupFragment newInstance(@NotNull String curOrderBy, @NotNull String videoType, @NotNull String keywords) {
            Intrinsics.checkNotNullParameter(curOrderBy, "curOrderBy");
            Intrinsics.checkNotNullParameter(videoType, "videoType");
            Intrinsics.checkNotNullParameter(keywords, "keywords");
            SearchResultGroupFragment searchResultGroupFragment = new SearchResultGroupFragment();
            searchResultGroupFragment.mCurVideoType = videoType;
            searchResultGroupFragment.mKeywords = keywords;
            searchResultGroupFragment.mOrderBy = curOrderBy;
            return searchResultGroupFragment;
        }
    }

    private final void setFrontendPadding(BaseViewHolder outHelper, LinearLayout recyclerView) {
        int paddingTop = recyclerView.getPaddingTop();
        int paddingBottom = recyclerView.getPaddingBottom();
        if (outHelper.getAdapterPosition() == 0) {
            recyclerView.setPadding(0, 0, 0, paddingBottom);
        } else {
            recyclerView.setPadding(0, paddingTop, 0, paddingBottom);
        }
    }

    private final void showCollectionLong(final BaseViewHolder outHelper, final HomeVideoGroupBean outItem) {
        outHelper.m3916f(R.id.v_listDivider, false);
        setFrontendPadding(outHelper, (LinearLayout) outHelper.m3912b(R.id.ll_module));
        C2354n.m2377B((LinearLayout) outHelper.m3912b(R.id.ll_titleLayout), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionLong$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
                Context requireContext = SearchResultGroupFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                HomeVideoGroupBean homeVideoGroupBean = outItem;
                companion.start(requireContext, homeVideoGroupBean.f9960id, homeVideoGroupBean.name);
            }
        }, 1);
        final ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_option);
        C2354n.m2377B(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionLong$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView2) {
                invoke2(imageView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                HomeDataHelper homeDataHelper = HomeDataHelper.INSTANCE;
                final HomeVideoGroupBean homeVideoGroupBean = HomeVideoGroupBean.this;
                String str = homeVideoGroupBean.f9960id;
                final ImageView imageView2 = imageView;
                final SearchResultGroupFragment searchResultGroupFragment = this;
                final BaseViewHolder baseViewHolder = outHelper;
                HomeDataHelper.checkLove$default(homeDataHelper, str, "3", new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionLong$1$2.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(CheckBean checkBean) {
                        invoke2(checkBean);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable CheckBean checkBean) {
                        if (checkBean == null) {
                            return;
                        }
                        ImageView imageView3 = imageView2;
                        final SearchResultGroupFragment searchResultGroupFragment2 = searchResultGroupFragment;
                        final BaseViewHolder baseViewHolder2 = baseViewHolder;
                        final HomeVideoGroupBean homeVideoGroupBean2 = homeVideoGroupBean;
                        final boolean hasLove = checkBean.hasLove();
                        OptionPopup.INSTANCE.showOptionPopup(imageView3, HomeDataHelper.INSTANCE.getVideoOptionItems(hasLove), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionLong$1$2$1$1$1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(String str2) {
                                invoke2(str2);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull String option) {
                                Intrinsics.checkNotNullParameter(option, "option");
                                if (TextUtils.equals("不感兴趣", option)) {
                                    SearchResultGroupFragment.this.getAdapter().remove(baseViewHolder2.getLayoutPosition());
                                    HomeDataHelper.INSTANCE.doDislike(homeVideoGroupBean2.f9960id, "3");
                                } else {
                                    HomeDataHelper homeDataHelper2 = HomeDataHelper.INSTANCE;
                                    String str2 = homeVideoGroupBean2.f9960id;
                                    final boolean z = hasLove;
                                    HomeDataHelper.doLove$default(homeDataHelper2, str2, "3", null, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionLong$1$2$1$1$1.1
                                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                        {
                                            super(1);
                                        }

                                        @Override // kotlin.jvm.functions.Function1
                                        public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                                            invoke2(obj);
                                            return Unit.INSTANCE;
                                        }

                                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                                        public final void invoke2(@Nullable Object obj) {
                                            C2354n.m2409L1(z ? "已取消收藏" : "已收藏");
                                        }
                                    }, null, 20, null);
                                }
                            }
                        });
                    }
                }, null, 8, null);
            }
        }, 1);
        String str = outItem.name;
        if (str == null) {
            str = "";
        }
        outHelper.m3919i(R.id.tv_title, str);
        outHelper.m3919i(R.id.tv_desc, ((Object) outItem.work_num) + "个作品·" + ((Object) outItem.collect_num) + "次收藏");
        RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setTag(outItem);
        recyclerView.setNestedScrollingEnabled(false);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        RecyclerView.Adapter adapter2 = adapter;
        if (adapter == null) {
            recyclerView.setLayoutManager(new GridLayoutManager(requireContext(), 2));
            if (recyclerView.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
                c4053a.m4576a(R.color.transparent);
                c4053a.f10336d = C2354n.m2437V(getContext(), 5.0d);
                c4053a.f10337e = C2354n.m2437V(getContext(), 8.0d);
                c4053a.f10339g = false;
                c4053a.f10340h = false;
                c4053a.f10338f = false;
                recyclerView.addItemDecoration(new GridItemDecoration(c4053a));
            }
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionLong$1$3
                {
                    super(R.layout.video_long_item1, null, 2, null);
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    Context requireContext = SearchResultGroupFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : true, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.m.d
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    SearchResultGroupFragment.m5978showCollectionLong$lambda2$lambda1$lambda0(SearchResultGroupFragment.this, baseQuickAdapter2, view, i2);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(outItem.items);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showCollectionLong$lambda-2$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5978showCollectionLong$lambda2$lambda1$lambda0(SearchResultGroupFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoItemBean");
        VideoItemBean videoItemBean = (VideoItemBean) obj;
        if (videoItemBean.getIsAd()) {
            return;
        }
        MovieDetailsActivity.Companion companion = MovieDetailsActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String str = videoItemBean.f10000id;
        if (str == null) {
            str = "";
        }
        companion.start(requireContext, str);
    }

    private final void showCollectionShort(final BaseViewHolder outHelper, final HomeVideoGroupBean outItem) {
        ArrayList arrayList;
        final HomeVideoGroupBean homeVideoGroupBean;
        outHelper.m3916f(R.id.v_listDivider, false);
        setFrontendPadding(outHelper, (LinearLayout) outHelper.m3912b(R.id.ll_module));
        C2354n.m2377B((LinearLayout) outHelper.m3912b(R.id.ll_titleLayout), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionShort$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
                Context requireContext = SearchResultGroupFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                HomeVideoGroupBean homeVideoGroupBean2 = outItem;
                companion.start(requireContext, homeVideoGroupBean2.f9960id, homeVideoGroupBean2.name);
            }
        }, 1);
        final ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_option);
        C2354n.m2377B(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionShort$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView2) {
                invoke2(imageView2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                HomeDataHelper homeDataHelper = HomeDataHelper.INSTANCE;
                final HomeVideoGroupBean homeVideoGroupBean2 = HomeVideoGroupBean.this;
                String str = homeVideoGroupBean2.f9960id;
                final ImageView imageView2 = imageView;
                final SearchResultGroupFragment searchResultGroupFragment = this;
                final BaseViewHolder baseViewHolder = outHelper;
                HomeDataHelper.checkLove$default(homeDataHelper, str, "3", new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionShort$1$2.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(CheckBean checkBean) {
                        invoke2(checkBean);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable CheckBean checkBean) {
                        if (checkBean == null) {
                            return;
                        }
                        ImageView imageView3 = imageView2;
                        final SearchResultGroupFragment searchResultGroupFragment2 = searchResultGroupFragment;
                        final BaseViewHolder baseViewHolder2 = baseViewHolder;
                        final HomeVideoGroupBean homeVideoGroupBean3 = homeVideoGroupBean2;
                        final boolean hasLove = checkBean.hasLove();
                        OptionPopup.INSTANCE.showOptionPopup(imageView3, HomeDataHelper.INSTANCE.getVideoOptionItems(hasLove), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionShort$1$2$1$1$1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(String str2) {
                                invoke2(str2);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull String option) {
                                Intrinsics.checkNotNullParameter(option, "option");
                                if (TextUtils.equals("不感兴趣", option)) {
                                    SearchResultGroupFragment.this.getAdapter().remove(baseViewHolder2.getLayoutPosition());
                                    HomeDataHelper.INSTANCE.doDislike(homeVideoGroupBean3.f9960id, "3");
                                } else {
                                    HomeDataHelper homeDataHelper2 = HomeDataHelper.INSTANCE;
                                    String str2 = homeVideoGroupBean3.f9960id;
                                    final boolean z = hasLove;
                                    HomeDataHelper.doLove$default(homeDataHelper2, str2, "3", null, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionShort$1$2$1$1$1.1
                                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                                        {
                                            super(1);
                                        }

                                        @Override // kotlin.jvm.functions.Function1
                                        public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                                            invoke2(obj);
                                            return Unit.INSTANCE;
                                        }

                                        /* renamed from: invoke, reason: avoid collision after fix types in other method */
                                        public final void invoke2(@Nullable Object obj) {
                                            C2354n.m2409L1(z ? "已取消收藏" : "已收藏");
                                        }
                                    }, null, 20, null);
                                }
                            }
                        });
                    }
                }, null, 8, null);
            }
        }, 1);
        String str = outItem.name;
        if (str == null) {
            str = "";
        }
        outHelper.m3919i(R.id.tv_title, str);
        outHelper.m3919i(R.id.tv_desc, ((Object) outItem.work_num) + "个作品·" + ((Object) outItem.collect_num) + "次收藏");
        RelativeLayout relativeLayout = (RelativeLayout) outHelper.m3912b(R.id.rl_leftVideo);
        List<VideoItemBean> items = outItem.items;
        ArrayList arrayList2 = new ArrayList();
        if ((items == null ? 0 : items.size()) > 0) {
            relativeLayout.setVisibility(0);
            Intrinsics.checkNotNullExpressionValue(items, "items");
            final VideoItemBean topVideoBean = (VideoItemBean) CollectionsKt___CollectionsKt.first((List) items);
            Context requireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            Intrinsics.checkNotNullExpressionValue(topVideoBean, "topVideoBean");
            ArrayList arrayList3 = arrayList2;
            VideoItemShowKt.showVideoItemMsg(requireContext, outHelper, topVideoBean, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
            int i2 = 0;
            for (VideoItemBean videoItemBean : items) {
                int i3 = i2 + 1;
                ArrayList arrayList4 = arrayList3;
                if (i2 > 0) {
                    arrayList4.add(videoItemBean);
                }
                i2 = i3;
                arrayList3 = arrayList4;
            }
            arrayList = arrayList3;
            homeVideoGroupBean = outItem;
            C2354n.m2377B(relativeLayout, 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionShort$1$3
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout2) {
                    invoke2(relativeLayout2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull RelativeLayout it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    if (VideoItemBean.this.getIsAd()) {
                        return;
                    }
                    HashMap hashMap = new HashMap();
                    String str2 = homeVideoGroupBean.f9960id;
                    if (str2 == null) {
                        str2 = "";
                    }
                    hashMap.put("group_id", str2);
                    PlayListActivity.Companion companion = PlayListActivity.INSTANCE;
                    Context requireContext2 = this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    companion.start(requireContext2, (r13 & 2) != 0 ? null : VideoItemBean.this.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
                }
            }, 1);
        } else {
            arrayList = arrayList2;
            homeVideoGroupBean = outItem;
            relativeLayout.setVisibility(8);
        }
        final RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setTag(homeVideoGroupBean);
        recyclerView.setNestedScrollingEnabled(false);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        RecyclerView.Adapter adapter2 = adapter;
        if (adapter == null) {
            recyclerView.setLayoutManager(new GridLayoutManager(requireContext(), 2));
            if (recyclerView.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
                c4053a.m4576a(R.color.transparent);
                c4053a.f10336d = C2354n.m2437V(getContext(), 5.0d);
                c4053a.f10337e = C2354n.m2437V(getContext(), 5.0d);
                c4053a.f10339g = false;
                c4053a.f10340h = false;
                c4053a.f10338f = false;
                recyclerView.addItemDecoration(new GridItemDecoration(c4053a));
            }
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$showCollectionShort$1$4
                {
                    super(R.layout.video_short_item4, null, 2, null);
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    Context requireContext2 = SearchResultGroupFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    VideoItemShowKt.showVideoItemMsg(requireContext2, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.m.e
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i4) {
                    SearchResultGroupFragment.m5979showCollectionShort$lambda6$lambda5$lambda4(RecyclerView.this, this, baseQuickAdapter2, view, i4);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(arrayList);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showCollectionShort$lambda-6$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5979showCollectionShort$lambda6$lambda5$lambda4(RecyclerView rv_list, SearchResultGroupFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        String str;
        Intrinsics.checkNotNullParameter(rv_list, "$rv_list");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoItemBean");
        VideoItemBean videoItemBean = (VideoItemBean) obj;
        if (videoItemBean.getIsAd()) {
            return;
        }
        HomeVideoGroupBean homeVideoGroupBean = (HomeVideoGroupBean) rv_list.getTag();
        HashMap hashMap = new HashMap();
        String str2 = "";
        if (homeVideoGroupBean != null && (str = homeVideoGroupBean.f9960id) != null) {
            str2 = str;
        }
        hashMap.put("group_id", str2);
        PlayListActivity.Companion companion = PlayListActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        companion.start(requireContext, (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @Nullable
    public HashMap<Integer, Integer> getAllItemType() {
        HashMap<Integer, Integer> hashMap = new HashMap<>();
        hashMap.put(-1, Integer.valueOf(R.layout.home_unknown));
        hashMap.put(2, Integer.valueOf(R.layout.block_style_collection_long));
        hashMap.put(3, Integer.valueOf(R.layout.block_style_collection_short));
        return hashMap;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        return new ItemDecorationV(C2354n.m2425R(requireContext(), 0.0f), C2354n.m2425R(requireContext(), 0.0f));
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new LinearLayoutManager(requireContext(), 1, false);
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
    public final void onUpdateSearch(@NotNull EventUpdate search) {
        Intrinsics.checkNotNullParameter(search, "search");
        if (search.getKeyword() != null) {
            this.mKeywords = search.getKeyword();
        } else if (search.getOrderBy() != null) {
            this.mOrderBy = search.getOrderBy();
        } else if (search.getVideoType() != null) {
            this.mCurVideoType = search.getVideoType();
        }
        reset();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        this.requestRoomParameter.put("page", String.valueOf(getCurrentPage()));
        this.requestRoomParameter.put("page_size", "15");
        HashMap<String, String> hashMap = this.requestRoomParameter;
        String str = this.mKeywords;
        if (str == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mKeywords");
            throw null;
        }
        hashMap.put("keywords", str);
        this.requestRoomParameter.put("pay_type", VideoTypeBean.video_type_free);
        this.requestRoomParameter.put("tag_id", "");
        this.requestRoomParameter.put("cat_id", "");
        this.requestRoomParameter.put("is_hot", "");
        this.requestRoomParameter.put("is_new", "");
        this.requestRoomParameter.put("ids", "");
        this.requestRoomParameter.put("position", "normal");
        this.requestRoomParameter.put("canvas", "group");
        HashMap<String, String> hashMap2 = this.requestRoomParameter;
        String str2 = this.mOrderBy;
        if (str2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mOrderBy");
            throw null;
        }
        hashMap2.put("order", str2);
        HashMap<String, String> hashMap3 = this.requestRoomParameter;
        String str3 = this.mCurVideoType;
        if (str3 != null) {
            hashMap3.put("video_type", str3);
            return C0917a.m222f(C0917a.f372a, "movie/search", HomeVideoGroupBean.class, this.requestRoomParameter, new Function1<List<? extends HomeVideoGroupBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$request$1
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(List<? extends HomeVideoGroupBean> list) {
                    invoke2(list);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable List<? extends HomeVideoGroupBean> list) {
                    SearchResultGroupFragment.this.didRequestComplete(list);
                }
            }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultGroupFragment$request$2
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
                    SearchResultGroupFragment.this.didRequestError();
                }
            }, false, false, null, false, 480);
        }
        Intrinsics.throwUninitializedPropertyAccessException("mCurVideoType");
        throw null;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull HomeVideoGroupBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        int itemType = item.getItemType();
        if (itemType == 2) {
            showCollectionLong(helper, item);
        } else {
            if (itemType != 3) {
                return;
            }
            showCollectionShort(helper, item);
        }
    }
}
