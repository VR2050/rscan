package com.jbzd.media.movecartoons.p396ui.index.found.child;

import android.content.Context;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseMultiItemQuickAdapter;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.CheckBean;
import com.jbzd.media.movecartoons.bean.response.FoundPickBean;
import com.jbzd.media.movecartoons.bean.response.HomeBlockBean;
import com.jbzd.media.movecartoons.bean.response.HomeVideoGroupBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.p396ui.dialog.OptionPopup;
import com.jbzd.media.movecartoons.p396ui.index.found.child.DayPickStyleAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.search.ModuleDetailActivity;
import com.jbzd.media.movecartoons.view.decoration.ItemDecorationH;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u000b\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001B\u0007¢\u0006\u0004\b\u000f\u0010\u0010J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u001f\u0010\t\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\t\u0010\bJ\u001f\u0010\n\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\n\u0010\bJ\u001f\u0010\u000b\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u000b\u0010\bJ\u001f\u0010\u000e\u001a\u00020\u00062\u0006\u0010\f\u001a\u00020\u00032\u0006\u0010\r\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u000e\u0010\b¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/child/DayPickStyleAdapter;", "Lcom/chad/library/adapter/base/BaseMultiItemQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/HomeBlockBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "outHelper", "outItem", "", "showCollectionLong", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HomeBlockBean;)V", "showCollectionShort", "showLong", "showShort", "helper", "item", "convert", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class DayPickStyleAdapter extends BaseMultiItemQuickAdapter<HomeBlockBean, BaseViewHolder> {
    public DayPickStyleAdapter() {
        super(null, 1, null);
        HashMap hashMap = new HashMap();
        hashMap.put(-1, Integer.valueOf(R.layout.home_unknown));
        hashMap.put(2, Integer.valueOf(R.layout.block_style_collection_long));
        hashMap.put(3, Integer.valueOf(R.layout.block_style_collection_short));
        hashMap.put(4, Integer.valueOf(R.layout.block_style_pick_long));
        hashMap.put(5, Integer.valueOf(R.layout.block_style_pick_short));
        for (Map.Entry entry : hashMap.entrySet()) {
            addItemType(((Number) entry.getKey()).intValue(), ((Number) entry.getValue()).intValue());
        }
    }

    private final void showCollectionLong(final BaseViewHolder outHelper, HomeBlockBean outItem) {
        outHelper.m3916f(R.id.v_listDivider, true);
        final HomeVideoGroupBean homeVideoGroupBean = outItem.long_video_group;
        C2354n.m2374A((LinearLayout) outHelper.m3912b(R.id.ll_titleLayout), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionLong$1$1
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
                Context context;
                Intrinsics.checkNotNullParameter(it, "it");
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
                context = DayPickStyleAdapter.this.getContext();
                HomeVideoGroupBean homeVideoGroupBean2 = homeVideoGroupBean;
                companion.start(context, homeVideoGroupBean2.f9960id, homeVideoGroupBean2.name);
            }
        }, 1);
        final ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_option);
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionLong$1$2
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
                final DayPickStyleAdapter dayPickStyleAdapter = this;
                final BaseViewHolder baseViewHolder = outHelper;
                HomeDataHelper.checkLove$default(homeDataHelper, str, "3", new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionLong$1$2.1
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
                        final DayPickStyleAdapter dayPickStyleAdapter2 = dayPickStyleAdapter;
                        final BaseViewHolder baseViewHolder2 = baseViewHolder;
                        final HomeVideoGroupBean homeVideoGroupBean3 = homeVideoGroupBean2;
                        final boolean hasLove = checkBean.hasLove();
                        OptionPopup.INSTANCE.showOptionPopup(imageView3, HomeDataHelper.INSTANCE.getVideoOptionItems(hasLove), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionLong$1$2$1$1$1
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
                                    DayPickStyleAdapter.this.remove(baseViewHolder2.getLayoutPosition());
                                    HomeDataHelper.INSTANCE.doDislike(homeVideoGroupBean3.f9960id, "3");
                                } else {
                                    HomeDataHelper homeDataHelper2 = HomeDataHelper.INSTANCE;
                                    String str2 = homeVideoGroupBean3.f9960id;
                                    final boolean z = hasLove;
                                    HomeDataHelper.doLove$default(homeDataHelper2, str2, "3", null, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionLong$1$2$1$1$1.1
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
        String str = homeVideoGroupBean.name;
        if (str == null) {
            str = "";
        }
        outHelper.m3919i(R.id.tv_title, str);
        outHelper.m3919i(R.id.tv_desc, ((Object) homeVideoGroupBean.work_num) + "个作品·" + ((Object) homeVideoGroupBean.collect_num) + "次收藏");
        RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setTag(homeVideoGroupBean);
        recyclerView.setNestedScrollingEnabled(false);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        RecyclerView.Adapter adapter2 = adapter;
        if (adapter == null) {
            recyclerView.setLayoutManager(new GridLayoutManager(getContext(), 2));
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
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionLong$1$3
                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    VideoItemShowKt.showVideoItemMsg(getContext(), helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : true, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.j.g.d
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    DayPickStyleAdapter.m5823showCollectionLong$lambda3$lambda2$lambda1(DayPickStyleAdapter.this, baseQuickAdapter2, view, i2);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(homeVideoGroupBean.items);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showCollectionLong$lambda-3$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5823showCollectionLong$lambda3$lambda2$lambda1(DayPickStyleAdapter this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoItemBean");
        VideoItemBean videoItemBean = (VideoItemBean) obj;
        if (videoItemBean.getIsAd()) {
            return;
        }
        MovieDetailsActivity.INSTANCE.start(this$0.getContext(), videoItemBean.f10000id);
    }

    private final void showCollectionShort(final BaseViewHolder outHelper, HomeBlockBean outItem) {
        ArrayList arrayList;
        final HomeVideoGroupBean homeVideoGroupBean;
        outHelper.m3916f(R.id.v_listDivider, true);
        final HomeVideoGroupBean homeVideoGroupBean2 = outItem.short_video_group;
        C2354n.m2374A((LinearLayout) outHelper.m3912b(R.id.ll_titleLayout), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionShort$1$1
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
                Context context;
                Intrinsics.checkNotNullParameter(it, "it");
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
                context = DayPickStyleAdapter.this.getContext();
                HomeVideoGroupBean homeVideoGroupBean3 = homeVideoGroupBean2;
                companion.start(context, homeVideoGroupBean3.f9960id, homeVideoGroupBean3.name);
            }
        }, 1);
        final ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_option);
        C2354n.m2374A(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionShort$1$2
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
                final HomeVideoGroupBean homeVideoGroupBean3 = HomeVideoGroupBean.this;
                String str = homeVideoGroupBean3.f9960id;
                final ImageView imageView2 = imageView;
                final DayPickStyleAdapter dayPickStyleAdapter = this;
                final BaseViewHolder baseViewHolder = outHelper;
                HomeDataHelper.checkLove$default(homeDataHelper, str, "3", new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionShort$1$2.1
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
                        final DayPickStyleAdapter dayPickStyleAdapter2 = dayPickStyleAdapter;
                        final BaseViewHolder baseViewHolder2 = baseViewHolder;
                        final HomeVideoGroupBean homeVideoGroupBean4 = homeVideoGroupBean3;
                        final boolean hasLove = checkBean.hasLove();
                        OptionPopup.INSTANCE.showOptionPopup(imageView3, HomeDataHelper.INSTANCE.getVideoOptionItems(hasLove), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionShort$1$2$1$1$1
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
                                    DayPickStyleAdapter.this.remove(baseViewHolder2.getLayoutPosition());
                                    HomeDataHelper.INSTANCE.doDislike(homeVideoGroupBean4.f9960id, "3");
                                } else {
                                    HomeDataHelper homeDataHelper2 = HomeDataHelper.INSTANCE;
                                    String str2 = homeVideoGroupBean4.f9960id;
                                    final boolean z = hasLove;
                                    HomeDataHelper.doLove$default(homeDataHelper2, str2, "3", null, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionShort$1$2$1$1$1.1
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
        String str = homeVideoGroupBean2.name;
        if (str == null) {
            str = "";
        }
        outHelper.m3919i(R.id.tv_title, str);
        outHelper.m3919i(R.id.tv_desc, ((Object) homeVideoGroupBean2.work_num) + "个作品·" + ((Object) homeVideoGroupBean2.collect_num) + "次收藏");
        RelativeLayout relativeLayout = (RelativeLayout) outHelper.m3912b(R.id.rl_leftVideo);
        List<VideoItemBean> items = homeVideoGroupBean2.items;
        ArrayList arrayList2 = new ArrayList();
        if ((items == null ? 0 : items.size()) > 0) {
            relativeLayout.setVisibility(0);
            Intrinsics.checkNotNullExpressionValue(items, "items");
            final VideoItemBean topVideoBean = (VideoItemBean) CollectionsKt___CollectionsKt.first((List) items);
            Context context = getContext();
            Intrinsics.checkNotNullExpressionValue(topVideoBean, "topVideoBean");
            ArrayList arrayList3 = arrayList2;
            VideoItemShowKt.showVideoItemMsg(context, outHelper, topVideoBean, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
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
            homeVideoGroupBean = homeVideoGroupBean2;
            C2354n.m2374A(relativeLayout, 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionShort$1$3
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
                    Context context2;
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
                    context2 = this.getContext();
                    companion.start(context2, (r13 & 2) != 0 ? null : VideoItemBean.this.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
                }
            }, 1);
        } else {
            arrayList = arrayList2;
            homeVideoGroupBean = homeVideoGroupBean2;
            relativeLayout.setVisibility(8);
        }
        final RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setTag(homeVideoGroupBean);
        recyclerView.setNestedScrollingEnabled(false);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        RecyclerView.Adapter adapter2 = adapter;
        if (adapter == null) {
            recyclerView.setLayoutManager(new GridLayoutManager(getContext(), 2));
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
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showCollectionShort$1$4
                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    VideoItemShowKt.showVideoItemMsg(getContext(), helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.j.g.c
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i4) {
                    DayPickStyleAdapter.m5824showCollectionShort$lambda7$lambda6$lambda5(RecyclerView.this, this, baseQuickAdapter2, view, i4);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(arrayList);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showCollectionShort$lambda-7$lambda-6$lambda-5, reason: not valid java name */
    public static final void m5824showCollectionShort$lambda7$lambda6$lambda5(RecyclerView rv_list, DayPickStyleAdapter this$0, BaseQuickAdapter adapter, View view, int i2) {
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
        PlayListActivity.INSTANCE.start(this$0.getContext(), (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
    }

    private final void showLong(BaseViewHolder outHelper, HomeBlockBean outItem) {
        List<VideoItemBean> list = outItem.long_videos;
        RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setTag(list);
        recyclerView.setNestedScrollingEnabled(false);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        RecyclerView.Adapter adapter2 = adapter;
        if (adapter == null) {
            recyclerView.setLayoutManager(new GridLayoutManager(getContext(), 2));
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
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showLong$1$1
                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    VideoItemShowKt.showVideoItemMsg(getContext(), helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : true, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.j.g.b
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    DayPickStyleAdapter.m5825showLong$lambda10$lambda9$lambda8(DayPickStyleAdapter.this, baseQuickAdapter2, view, i2);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(list);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showLong$lambda-10$lambda-9$lambda-8, reason: not valid java name */
    public static final void m5825showLong$lambda10$lambda9$lambda8(DayPickStyleAdapter this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.VideoItemBean");
        VideoItemBean videoItemBean = (VideoItemBean) obj;
        if (videoItemBean.getIsAd()) {
            return;
        }
        MovieDetailsActivity.INSTANCE.start(this$0.getContext(), videoItemBean.f10000id);
    }

    private final void showShort(BaseViewHolder outHelper, HomeBlockBean outItem) {
        List<VideoItemBean> list = outItem.short_videos;
        final RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setTag(outItem);
        recyclerView.setNestedScrollingEnabled(false);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        RecyclerView.Adapter adapter2 = adapter;
        if (adapter == null) {
            recyclerView.setLayoutManager(new LinearLayoutManager(getContext(), 0, false));
            if (recyclerView.getItemDecorationCount() == 0) {
                recyclerView.addItemDecoration(new ItemDecorationH(C2354n.m2425R(getContext(), 5.0f)));
            }
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.found.child.DayPickStyleAdapter$showShort$1$1
                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    VideoItemShowKt.showVideoItemMsg(getContext(), helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.j.g.a
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    DayPickStyleAdapter.m5826showShort$lambda14$lambda13$lambda12(RecyclerView.this, this, baseQuickAdapter2, view, i2);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(list);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showShort$lambda-14$lambda-13$lambda-12, reason: not valid java name */
    public static final void m5826showShort$lambda14$lambda13$lambda12(RecyclerView rv_list, DayPickStyleAdapter this$0, BaseQuickAdapter adapter, View view, int i2) {
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
        HomeBlockBean homeBlockBean = (HomeBlockBean) rv_list.getTag();
        HashMap hashMap = new HashMap();
        FoundPickBean foundPickBean = homeBlockBean == null ? null : homeBlockBean.pickBean;
        String str2 = "";
        if (foundPickBean != null && (str = foundPickBean.f9952id) != null) {
            str2 = str;
        }
        hashMap.put("video_pick_id", str2);
        hashMap.put("has_image", HomeDataHelper.INSTANCE.getRequestHasImage(true));
        PlayListActivity.INSTANCE.start(this$0.getContext(), (r13 & 2) != 0 ? null : videoItemBean.f10000id, (r13 & 4) != 0 ? null : hashMap, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : false);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(@NotNull BaseViewHolder helper, @NotNull HomeBlockBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        int itemType = item.getItemType();
        if (itemType == 2) {
            showCollectionLong(helper, item);
            return;
        }
        if (itemType == 3) {
            showCollectionShort(helper, item);
        } else if (itemType == 4) {
            showLong(helper, item);
        } else {
            if (itemType != 5) {
                return;
            }
            showShort(helper, item);
        }
    }
}
