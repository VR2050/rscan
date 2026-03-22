package com.jbzd.media.movecartoons.p396ui.index.found;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import com.jbzd.media.movecartoons.bean.response.CheckBean;
import com.jbzd.media.movecartoons.bean.response.HomeVideoGroupBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.core.BaseMutiListFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.OptionPopup;
import com.jbzd.media.movecartoons.p396ui.index.found.GroupListFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.jbzd.media.movecartoons.p396ui.search.ModuleDetailActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0869q;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p293n.p294a.C2657k0;
import p005b.p293n.p294a.InterfaceC2652i;
import p379c.p380a.InterfaceC3053d1;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 .2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001.B\u0007¢\u0006\u0004\b,\u0010-J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u001f\u0010\t\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\t\u0010\bJ2\u0010\u0010\u001a\u00020\u00062!\u0010\u000f\u001a\u001d\u0012\u0013\u0012\u00110\u000b¢\u0006\f\b\f\u0012\b\b\r\u0012\u0004\b\b(\u000e\u0012\u0004\u0012\u00020\u00060\nH\u0003¢\u0006\u0004\b\u0010\u0010\u0011J)\u0010\u0015\u001a\u001e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00130\u0012j\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u0013`\u0014¢\u0006\u0004\b\u0015\u0010\u0016J/\u0010\u0018\u001a\"\u0012\u0004\u0012\u00020\u0017\u0012\u0004\u0012\u00020\u0017\u0018\u00010\u0012j\u0010\u0012\u0004\u0012\u00020\u0017\u0012\u0004\u0012\u00020\u0017\u0018\u0001`\u0014H\u0016¢\u0006\u0004\b\u0018\u0010\u0016J\u000f\u0010\u001a\u001a\u00020\u0019H\u0016¢\u0006\u0004\b\u001a\u0010\u001bJ\u001f\u0010\u001e\u001a\u00020\u00062\u0006\u0010\u001c\u001a\u00020\u00032\u0006\u0010\u001d\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u001e\u0010\bR\u001d\u0010#\u001a\u00020\u00138B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"R9\u0010&\u001a\u001e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u00130\u0012j\u000e\u0012\u0004\u0012\u00020\u0013\u0012\u0004\u0012\u00020\u0013`\u00148F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010 \u001a\u0004\b%\u0010\u0016R\u001d\u0010+\u001a\u00020'8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010 \u001a\u0004\b)\u0010*¨\u0006/"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/GroupListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseMutiListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/HomeVideoGroupBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "outHelper", "outItem", "", "showCollectionLong", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HomeVideoGroupBean;)V", "showCollectionShort", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "pass", "resultBlock", "permissionCheck", "(Lkotlin/jvm/functions/Function1;)V", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "getRequestVideoBody", "()Ljava/util/HashMap;", "", "getAllItemType", "Lc/a/d1;", "request", "()Lc/a/d1;", "helper", "item", "bindItem", "mOrderBy$delegate", "Lkotlin/Lazy;", "getMOrderBy", "()Ljava/lang/String;", "mOrderBy", "requestRoomParameter$delegate", "getRequestRoomParameter", "requestRoomParameter", "Lb/a/a/a/a/q;", "downloadUtils$delegate", "getDownloadUtils", "()Lb/a/a/a/a/q;", "downloadUtils", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class GroupListFragment extends BaseMutiListFragment<HomeVideoGroupBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String key_order_by = "order_by";

    /* renamed from: mOrderBy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mOrderBy = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$mOrderBy$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            Bundle arguments = GroupListFragment.this.getArguments();
            String string = arguments == null ? null : arguments.getString("order_by");
            if (string != null) {
                int hashCode = string.hashCode();
                if (hashCode != 824488) {
                    if (hashCode != 843440) {
                        if (hashCode == 846317 && string.equals(PickGroupFragment.type_hot)) {
                            return "love";
                        }
                    } else if (string.equals(PickGroupFragment.type_new)) {
                        return BloggerOrderBean.order_new;
                    }
                } else if (string.equals(PickGroupFragment.type_recommend)) {
                    return "recommend_at";
                }
            }
            return "";
        }
    });

    /* renamed from: requestRoomParameter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy requestRoomParameter = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$requestRoomParameter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return GroupListFragment.this.getRequestVideoBody();
        }
    });

    /* renamed from: downloadUtils$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy downloadUtils = LazyKt__LazyJVMKt.lazy(new Function0<C0869q>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$downloadUtils$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final C0869q invoke() {
            Context requireContext = GroupListFragment.this.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            return new C0869q(requireContext);
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\u0007\u001a\u00020\u00028\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/found/GroupListFragment$Companion;", "", "", "order", "Lcom/jbzd/media/movecartoons/ui/index/found/GroupListFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/found/GroupListFragment;", "key_order_by", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final GroupListFragment newInstance(@NotNull String order) {
            Intrinsics.checkNotNullParameter(order, "order");
            GroupListFragment groupListFragment = new GroupListFragment();
            Bundle bundle = new Bundle();
            bundle.putString("order_by", order);
            Unit unit = Unit.INSTANCE;
            groupListFragment.setArguments(bundle);
            return groupListFragment;
        }
    }

    private final C0869q getDownloadUtils() {
        return (C0869q) this.downloadUtils.getValue();
    }

    private final String getMOrderBy() {
        return (String) this.mOrderBy.getValue();
    }

    @SuppressLint({"CheckResult"})
    private final void permissionCheck(final Function1<? super Boolean, Unit> resultBlock) {
        C2657k0 c2657k0 = new C2657k0(getActivity());
        c2657k0.m3155a("android.permission.READ_EXTERNAL_STORAGE");
        c2657k0.m3155a("android.permission.WRITE_EXTERNAL_STORAGE");
        c2657k0.m3156b(new InterfaceC2652i() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$permissionCheck$1
            @Override // p005b.p293n.p294a.InterfaceC2652i
            public void onDenied(@NotNull List<String> permissions, boolean doNotAskAgain) {
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                if (!doNotAskAgain) {
                    C4325a.m4899b(GroupListFragment.this.requireContext(), "没有权限").show();
                } else {
                    C4325a.m4899b(GroupListFragment.this.requireContext(), "被永久拒绝授权").show();
                    C2657k0.m3154c(GroupListFragment.this, permissions);
                }
            }

            @Override // p005b.p293n.p294a.InterfaceC2652i
            public void onGranted(@NotNull List<String> permissions, boolean allGranted) {
                Intrinsics.checkNotNullParameter(permissions, "permissions");
                if (allGranted) {
                    resultBlock.invoke(Boolean.TRUE);
                } else {
                    C4325a.m4899b(GroupListFragment.this.requireContext(), "获取部分权限成功，但部分权限未正常授予").show();
                }
            }
        });
    }

    private final void showCollectionLong(final BaseViewHolder outHelper, final HomeVideoGroupBean outItem) {
        outHelper.m3916f(R.id.v_listDivider, false);
        C2354n.m2377B((LinearLayout) outHelper.m3912b(R.id.ll_titleLayout), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionLong$1$1
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
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.Companion;
                Context requireContext = GroupListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                HomeVideoGroupBean homeVideoGroupBean = outItem;
                companion.start(requireContext, homeVideoGroupBean.f9960id, homeVideoGroupBean.name);
            }
        }, 1);
        final ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_option);
        C2354n.m2377B(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionLong$1$2
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
                final GroupListFragment groupListFragment = this;
                final BaseViewHolder baseViewHolder = outHelper;
                HomeDataHelper.checkLove$default(homeDataHelper, str, "3", new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionLong$1$2.1
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
                        final GroupListFragment groupListFragment2 = groupListFragment;
                        final BaseViewHolder baseViewHolder2 = baseViewHolder;
                        final HomeVideoGroupBean homeVideoGroupBean2 = homeVideoGroupBean;
                        final boolean hasLove = checkBean.hasLove();
                        OptionPopup.Companion.showOptionPopup(imageView3, HomeDataHelper.INSTANCE.getVideoOptionItems(hasLove), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionLong$1$2$1$1$1
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
                                    GroupListFragment.this.getAdapter().remove(baseViewHolder2.getLayoutPosition());
                                    HomeDataHelper.INSTANCE.doDislike(homeVideoGroupBean2.f9960id, "3");
                                } else {
                                    HomeDataHelper homeDataHelper2 = HomeDataHelper.INSTANCE;
                                    String str2 = homeVideoGroupBean2.f9960id;
                                    final boolean z = hasLove;
                                    HomeDataHelper.doLove$default(homeDataHelper2, str2, "3", null, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionLong$1$2$1$1$1.1
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
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionLong$1$3
                {
                    super(R.layout.video_long_item1, null, 2, null);
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    Context requireContext = GroupListFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                    VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : true, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.j.e
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    GroupListFragment.m5821showCollectionLong$lambda3$lambda2$lambda1(GroupListFragment.this, baseQuickAdapter2, view, i2);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(outItem.items);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showCollectionLong$lambda-3$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5821showCollectionLong$lambda3$lambda2$lambda1(GroupListFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
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
        C2354n.m2377B((LinearLayout) outHelper.m3912b(R.id.ll_titleLayout), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionShort$1$1
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
                ModuleDetailActivity.Companion companion = ModuleDetailActivity.Companion;
                Context requireContext = GroupListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                HomeVideoGroupBean homeVideoGroupBean2 = outItem;
                companion.start(requireContext, homeVideoGroupBean2.f9960id, homeVideoGroupBean2.name);
            }
        }, 1);
        final ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_option);
        C2354n.m2377B(imageView, 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionShort$1$2
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
                final GroupListFragment groupListFragment = this;
                final BaseViewHolder baseViewHolder = outHelper;
                HomeDataHelper.checkLove$default(homeDataHelper, str, "3", new Function1<CheckBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionShort$1$2.1
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
                        final GroupListFragment groupListFragment2 = groupListFragment;
                        final BaseViewHolder baseViewHolder2 = baseViewHolder;
                        final HomeVideoGroupBean homeVideoGroupBean3 = homeVideoGroupBean2;
                        final boolean hasLove = checkBean.hasLove();
                        OptionPopup.Companion.showOptionPopup(imageView3, HomeDataHelper.INSTANCE.getVideoOptionItems(hasLove), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionShort$1$2$1$1$1
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
                                    GroupListFragment.this.getAdapter().remove(baseViewHolder2.getLayoutPosition());
                                    HomeDataHelper.INSTANCE.doDislike(homeVideoGroupBean3.f9960id, "3");
                                } else {
                                    HomeDataHelper homeDataHelper2 = HomeDataHelper.INSTANCE;
                                    String str2 = homeVideoGroupBean3.f9960id;
                                    final boolean z = hasLove;
                                    HomeDataHelper.doLove$default(homeDataHelper2, str2, "3", null, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionShort$1$2$1$1$1.1
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
            C2354n.m2377B(relativeLayout, 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionShort$1$3
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
            BaseQuickAdapter<VideoItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<VideoItemBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$showCollectionShort$1$4
                {
                    super(R.layout.video_short_item4, null, 2, null);
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                public void convert(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    Context requireContext2 = GroupListFragment.this.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                    VideoItemShowKt.showVideoItemMsg(requireContext2, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : true, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : false);
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.j.f
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i4) {
                    GroupListFragment.m5822showCollectionShort$lambda7$lambda6$lambda5(RecyclerView.this, this, baseQuickAdapter2, view, i4);
                }
            });
            recyclerView.setAdapter(baseQuickAdapter);
            adapter2 = baseQuickAdapter;
        }
        ((BaseQuickAdapter) adapter2).setNewData(arrayList);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: showCollectionShort$lambda-7$lambda-6$lambda-5, reason: not valid java name */
    public static final void m5822showCollectionShort$lambda7$lambda6$lambda5(RecyclerView rv_list, GroupListFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
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
        hashMap.put(1, Integer.valueOf(R.layout.found_block_tag));
        hashMap.put(2, Integer.valueOf(R.layout.found_block_collection_long));
        hashMap.put(3, Integer.valueOf(R.layout.found_block_collection_short));
        hashMap.put(4, Integer.valueOf(R.layout.found_block_app));
        hashMap.put(5, Integer.valueOf(R.layout.found_block_day_select));
        return hashMap;
    }

    @NotNull
    public final HashMap<String, String> getRequestRoomParameter() {
        return (HashMap) this.requestRoomParameter.getValue();
    }

    @NotNull
    public final HashMap<String, String> getRequestVideoBody() {
        HashMap<String, String> hashMap = new HashMap<>();
        hashMap.put("order_by", getMOrderBy());
        hashMap.put("canvas", "group");
        return hashMap;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        getRequestRoomParameter().put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, "movie/search", HomeVideoGroupBean.class, getRequestRoomParameter(), new Function1<List<? extends HomeVideoGroupBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$request$1
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
                GroupListFragment.this.didRequestComplete(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.found.GroupListFragment$request$2
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
                GroupListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull HomeVideoGroupBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        String str = item.group_type;
        if (Intrinsics.areEqual(str, "short")) {
            showCollectionShort(helper, item);
        } else if (Intrinsics.areEqual(str, "long")) {
            showCollectionLong(helper, item);
        }
    }
}
