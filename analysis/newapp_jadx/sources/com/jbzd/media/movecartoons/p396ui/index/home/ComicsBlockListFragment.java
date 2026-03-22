package com.jbzd.media.movecartoons.p396ui.index.home;

import android.annotation.SuppressLint;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.RequiresApi;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.home.HomeTabBean;
import com.jbzd.media.movecartoons.core.BaseMutiListFragment;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailActivity;
import com.jbzd.media.movecartoons.p396ui.index.home.ComicsBlockListFragment;
import com.jbzd.media.movecartoons.p396ui.search.ComicsModuleDetailActivity;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
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
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0014\u0018\u0000 72\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00017B\u0007¢\u0006\u0004\b5\u00106J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J/\u0010\u000e\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\u000b2\u0006\u0010\r\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ/\u0010\u0013\u001a\u00020\u00052\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u00022\u0006\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0012\u001a\u00020\u000bH\u0003¢\u0006\u0004\b\u0013\u0010\u0014J\u001f\u0010\u0016\u001a\u00020\u00052\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\n\u001a\u00020\u0015H\u0002¢\u0006\u0004\b\u0016\u0010\u0017J'\u0010\u001b\u001a\u00020\u00052\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\n\u001a\u00020\u00152\u0006\u0010\u001a\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u001b\u0010\u001cJ\u000f\u0010\u001e\u001a\u00020\u001dH\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ/\u0010\"\u001a\"\u0012\u0004\u0012\u00020\u000b\u0012\u0004\u0012\u00020\u000b\u0018\u00010 j\u0010\u0012\u0004\u0012\u00020\u000b\u0012\u0004\u0012\u00020\u000b\u0018\u0001`!H\u0016¢\u0006\u0004\b\"\u0010#J\u000f\u0010%\u001a\u00020$H\u0016¢\u0006\u0004\b%\u0010&J\u0017\u0010(\u001a\u00020\u00052\b\u0010'\u001a\u0004\u0018\u00010\u001d¢\u0006\u0004\b(\u0010)J\u001f\u0010,\u001a\u00020\u00052\u0006\u0010*\u001a\u00020\u00102\u0006\u0010+\u001a\u00020\u0002H\u0016¢\u0006\u0004\b,\u0010-R9\u00101\u001a\u001e\u0012\u0004\u0012\u00020\u001d\u0012\u0004\u0012\u00020\u001d0 j\u000e\u0012\u0004\u0012\u00020\u001d\u0012\u0004\u0012\u00020\u001d`!8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b.\u0010/\u001a\u0004\b0\u0010#R\u001f\u00104\u001a\u0004\u0018\u00010\u001d8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b2\u0010/\u001a\u0004\b3\u0010\u001f¨\u00068"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/ComicsBlockListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseMutiListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean;", "Landroid/view/ViewGroup;", "parentView", "", "initBannerGone", "(Landroid/view/ViewGroup;)V", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list", "outItem", "", "layout", "span", "setRecyclerView", "(Landroidx/recyclerview/widget/RecyclerView;Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean;II)V", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "outHelper", "mainSpan", "showComicsList", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean;II)V", "Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;", "showAD", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;)V", "Landroid/view/View;", "view", "layoutPosition", "onChangeClick", "(Landroid/view/View;Lcom/jbzd/media/movecartoons/bean/response/home/HomeTabBean;I)V", "", "getEmptyTips", "()Ljava/lang/String;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "getAllItemType", "()Ljava/util/HashMap;", "Lc/a/d1;", "request", "()Lc/a/d1;", "orderBy", "updateOrderBy", "(Ljava/lang/String;)V", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/HomeComicsBlockBean;)V", "mParams$delegate", "Lkotlin/Lazy;", "getMParams", "mParams", "filter$delegate", "getFilter", ComicsBlockListFragment.KEY_FILTER, "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsBlockListFragment extends BaseMutiListFragment<HomeComicsBlockBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static final String KEY_FILTER = "filter";

    /* renamed from: filter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy filter = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$filter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            Bundle arguments = ComicsBlockListFragment.this.getArguments();
            if (arguments == null) {
                return null;
            }
            return arguments.getString("filter");
        }
    });

    /* renamed from: mParams$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mParams = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$mParams$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return new HashMap<>();
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\u0007\u001a\u00020\u00028\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/ComicsBlockListFragment$Companion;", "", "", ComicsBlockListFragment.KEY_FILTER, "Lcom/jbzd/media/movecartoons/ui/index/home/ComicsBlockListFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/home/ComicsBlockListFragment;", "KEY_FILTER", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ComicsBlockListFragment newInstance(@Nullable String filter) {
            ComicsBlockListFragment comicsBlockListFragment = new ComicsBlockListFragment();
            Bundle bundle = new Bundle();
            bundle.putString(ComicsBlockListFragment.KEY_FILTER, filter);
            Unit unit = Unit.INSTANCE;
            comicsBlockListFragment.setArguments(bundle);
            return comicsBlockListFragment;
        }
    }

    private final String getFilter() {
        return (String) this.filter.getValue();
    }

    private final HashMap<String, String> getMParams() {
        return (HashMap) this.mParams.getValue();
    }

    private final void initBannerGone(ViewGroup parentView) {
        parentView.setVisibility(8);
    }

    private final void onChangeClick(View view, final HomeTabBean outItem, final int layoutPosition) {
        String str = outItem.block.get(0).filter;
        HashMap hashMap = new HashMap();
        if (!(str == null || str.length() == 0)) {
            try {
                JSONObject jSONObject = new JSONObject(str);
                Iterator<String> keys = jSONObject.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    String value = jSONObject.getString(key);
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    Intrinsics.checkNotNullExpressionValue(value, "value");
                    hashMap.put(key, value);
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        hashMap.put("page", String.valueOf(outItem.nextPage));
        hashMap.put("page_size", String.valueOf(outItem.block.get(0).page_size));
        hashMap.put("is_change", "1");
        C0917a.m222f(C0917a.f372a, "movie/search", VideoItemBean.class, hashMap, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$onChangeClick$1
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
                try {
                    if (C2354n.m2414N0(list)) {
                        HomeTabBean homeTabBean = HomeTabBean.this;
                        Objects.requireNonNull(list, "null cannot be cast to non-null type java.util.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean>{ kotlin.collections.TypeAliasesKt.ArrayList<com.jbzd.media.movecartoons.bean.response.VideoItemBean> }");
                        homeTabBean.items = (ArrayList) list;
                        homeTabBean.nextPage++;
                        this.getAdapter().notifyItemChanged(layoutPosition);
                    } else {
                        HomeTabBean homeTabBean2 = HomeTabBean.this;
                        if (homeTabBean2.nextPage != 1) {
                            homeTabBean2.nextPage = 1;
                        }
                    }
                } catch (Exception unused) {
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$onChangeClick$2
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

    private final void setRecyclerView(RecyclerView rv_list, final HomeComicsBlockBean outItem, final int layout, int span) {
        if (rv_list.getAdapter() == null) {
            if (span == 0) {
                rv_list.setLayoutManager(new LinearLayoutManager(requireContext(), 0, false));
            } else {
                rv_list.setLayoutManager(new GridLayoutManager(requireContext(), span));
            }
            if (rv_list.getItemDecorationCount() == 0) {
                if (outItem.getItemType() == 1) {
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
                    c4053a.m4576a(R.color.transparent);
                    c4053a.f10336d = C2354n.m2437V(getContext(), 2.0d);
                    c4053a.f10337e = C2354n.m2437V(getContext(), 3.0d);
                    c4053a.f10339g = false;
                    c4053a.f10340h = false;
                    c4053a.f10338f = false;
                    rv_list.addItemDecoration(new GridItemDecoration(c4053a));
                } else {
                    GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(getContext());
                    c4053a2.m4576a(R.color.transparent);
                    c4053a2.f10336d = C2354n.m2437V(getContext(), 3.0d);
                    c4053a2.f10337e = C2354n.m2437V(getContext(), 6.0d);
                    c4053a2.f10339g = false;
                    c4053a2.f10340h = false;
                    c4053a2.f10338f = false;
                    rv_list.addItemDecoration(new GridItemDecoration(c4053a2));
                }
            }
            BaseQuickAdapter<HomeComicsBlockBean.ComicsItemBean, BaseViewHolder> baseQuickAdapter = new BaseQuickAdapter<HomeComicsBlockBean.ComicsItemBean, BaseViewHolder>(outItem, layout) { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$setRecyclerView$1
                public final /* synthetic */ int $layout;
                public final /* synthetic */ HomeComicsBlockBean $outItem;

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(layout, null, 2, null);
                    this.$layout = layout;
                }

                @Override // com.chad.library.adapter.base.BaseQuickAdapter
                @RequiresApi(23)
                public void convert(@NotNull BaseViewHolder helper, @NotNull HomeComicsBlockBean.ComicsItemBean item) {
                    Intrinsics.checkNotNullParameter(helper, "helper");
                    Intrinsics.checkNotNullParameter(item, "item");
                    C2354n.m2463c2(ComicsBlockListFragment.this).m3298p(item.img).m3292f0().m757R((ImageView) helper.m3912b(R.id.img_cover));
                    View view = helper.m3912b(R.id.img_cover);
                    Intrinsics.checkNotNullParameter(view, "view");
                    view.setOutlineProvider(new C0859m0(6.0d));
                    view.setClipToOutline(true);
                    helper.m3919i(R.id.tv_comics_name, item.name);
                    helper.m3919i(R.id.tv_comics_category_subtitle, item.category + Typography.middleDot + ((Object) item.sub_title));
                    ImageTextView imageTextView = (ImageTextView) helper.m3912b(R.id.txt_num_click);
                    imageTextView.setText(item.sub_title);
                    imageTextView.setCompoundDrawables(null, null, null, null);
                    ImageView imageView = (ImageView) helper.m3912b(R.id.iv_ico_type);
                    imageView.setVisibility(!item.ico.equals("") ? 0 : 8);
                    if (item.ico.equals(VideoTypeBean.video_type_free)) {
                        C2354n.m2463c2(ComicsBlockListFragment.this).m3297o(Integer.valueOf(R.drawable.icon_mh_free)).m3295i0().m757R(imageView);
                    } else if (item.ico.equals(BloggerOrderBean.order_new)) {
                        C2354n.m2463c2(ComicsBlockListFragment.this).m3297o(Integer.valueOf(R.drawable.icon_mh_new)).m3295i0().m757R(imageView);
                    } else {
                        C2354n.m2463c2(ComicsBlockListFragment.this).m3297o(Integer.valueOf(R.drawable.icon_mh_hot)).m3295i0().m757R(imageView);
                    }
                    if (helper.m3914d(R.id.space_left)) {
                        helper.m3912b(R.id.space_left).setVisibility(8);
                        int size = getData().size();
                        if (size > 0) {
                            int i2 = 0;
                            while (true) {
                                int i3 = i2 + 1;
                                if (Intrinsics.areEqual(getData().get(i2), item) && i2 == 0) {
                                    helper.m3912b(R.id.space_left).setVisibility(0);
                                    helper.m3912b(R.id.space_left).setTag(this.$outItem);
                                }
                                if (i3 >= size) {
                                    break;
                                } else {
                                    i2 = i3;
                                }
                            }
                        }
                    }
                    if (helper.m3914d(R.id.tv_slide_more)) {
                        helper.m3912b(R.id.tv_slide_more).setVisibility(8);
                        View m3912b = helper.m3912b(R.id.tv_slide_more);
                        final ComicsBlockListFragment comicsBlockListFragment = ComicsBlockListFragment.this;
                        final HomeComicsBlockBean homeComicsBlockBean = this.$outItem;
                        C2354n.m2533z(m3912b, 500L, new Function1<View, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$setRecyclerView$1$convert$1
                            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                            {
                                super(1);
                            }

                            @Override // kotlin.jvm.functions.Function1
                            public /* bridge */ /* synthetic */ Unit invoke(View view2) {
                                invoke2(view2);
                                return Unit.INSTANCE;
                            }

                            /* renamed from: invoke, reason: avoid collision after fix types in other method */
                            public final void invoke2(@NotNull View it) {
                                Intrinsics.checkNotNullParameter(it, "it");
                                ComicsModuleDetailActivity.Companion companion = ComicsModuleDetailActivity.INSTANCE;
                                Context requireContext = ComicsBlockListFragment.this.requireContext();
                                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                                String str = homeComicsBlockBean.name;
                                Intrinsics.checkNotNullExpressionValue(str, "outItem.name");
                                String str2 = homeComicsBlockBean.filter;
                                Intrinsics.checkNotNullExpressionValue(str2, "outItem.filter");
                                companion.start(requireContext, str, str2, "");
                            }
                        });
                    }
                }
            };
            baseQuickAdapter.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.k.b
                @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
                public final void onItemClick(BaseQuickAdapter baseQuickAdapter2, View view, int i2) {
                    ComicsBlockListFragment.m5828setRecyclerView$lambda3$lambda2(ComicsBlockListFragment.this, baseQuickAdapter2, view, i2);
                }
            });
            rv_list.setAdapter(baseQuickAdapter);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: setRecyclerView$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5828setRecyclerView$lambda3$lambda2(ComicsBlockListFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean.ComicsItemBean");
        ComicsDetailActivity.Companion companion = ComicsDetailActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String str = ((HomeComicsBlockBean.ComicsItemBean) obj).f9958id;
        Intrinsics.checkNotNullExpressionValue(str, "mComicsItemBean.id");
        companion.start(requireContext, str);
    }

    private final void showAD(BaseViewHolder outHelper, HomeTabBean outItem) {
        final AdBean adBean = outItem.f10016ad;
        C2354n.m2463c2(this).m3298p(adBean == null ? null : adBean.content).m3295i0().m757R((ImageView) outHelper.m3912b(R.id.iv_img));
        C2354n.m2374A(outHelper.m3912b(R.id.ll_adParent_new), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$showAD$1$1
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
                C0840d.a aVar = C0840d.f235a;
                Context requireContext = ComicsBlockListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                AdBean ad = adBean;
                Intrinsics.checkNotNullExpressionValue(ad, "ad");
                aVar.m176b(requireContext, ad);
            }
        }, 1);
    }

    @SuppressLint({"SuspiciousIndentation"})
    private final void showComicsList(BaseViewHolder outHelper, final HomeComicsBlockBean outItem, int layout, int mainSpan) {
        if (outHelper.m3914d(R.id.v_listDivider)) {
            outHelper.m3916f(R.id.v_listDivider, false);
        }
        ImageView imageView = (ImageView) outHelper.m3912b(R.id.iv_modulename_left);
        if (outItem.ico.equals(BloggerOrderBean.order_new)) {
            C2354n.m2463c2(this).m3297o(Integer.valueOf(R.drawable.icon_module_new)).m3295i0().m757R(imageView);
        } else if (outItem.ico.equals("hot")) {
            C2354n.m2463c2(this).m3297o(Integer.valueOf(R.drawable.icon_module_hot)).m3295i0().m757R(imageView);
        } else {
            C2354n.m2463c2(this).m3297o(Integer.valueOf(R.drawable.icon_module_star)).m3295i0().m757R(imageView);
        }
        String str = outItem.name;
        if (str == null) {
            str = "";
        }
        outHelper.m3919i(R.id.tv_title_module, str);
        C2354n.m2374A((ImageTextView) outHelper.m3912b(R.id.itv_header_more), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$showComicsList$1$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsModuleDetailActivity.Companion companion = ComicsModuleDetailActivity.INSTANCE;
                Context requireContext = ComicsBlockListFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                String str2 = outItem.name;
                Intrinsics.checkNotNullExpressionValue(str2, "outItem.name");
                String str3 = outItem.filter;
                Intrinsics.checkNotNullExpressionValue(str3, "outItem.filter");
                companion.start(requireContext, str2, str3, "");
            }
        }, 1);
        RecyclerView recyclerView = (RecyclerView) outHelper.m3912b(R.id.rv_list);
        recyclerView.setNestedScrollingEnabled(false);
        setRecyclerView(recyclerView, outItem, layout, mainSpan);
        ArrayList<HomeComicsBlockBean.ComicsItemBean> arrayList = outItem.items;
        Intrinsics.checkNotNullExpressionValue(arrayList, "outItem.items");
        List mutableList = CollectionsKt___CollectionsKt.toMutableList((Collection) arrayList);
        recyclerView.setTag(mutableList);
        RecyclerView.Adapter adapter = recyclerView.getAdapter();
        Objects.requireNonNull(adapter, "null cannot be cast to non-null type com.chad.library.adapter.base.BaseQuickAdapter<com.jbzd.media.movecartoons.bean.response.HomeComicsBlockBean.ComicsItemBean, com.chad.library.adapter.base.viewholder.BaseViewHolder>");
        ((BaseQuickAdapter) adapter).setNewData(mutableList);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @Nullable
    public HashMap<Integer, Integer> getAllItemType() {
        HashMap<Integer, Integer> hashMap = new HashMap<>();
        hashMap.put(1, Integer.valueOf(R.layout.block_style_module_simple));
        Integer valueOf = Integer.valueOf(R.layout.block_style_module_portrait_grid);
        hashMap.put(2, valueOf);
        hashMap.put(3, valueOf);
        return hashMap;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @NotNull
    public String getEmptyTips() {
        return "人家也是有底线的啦…";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        String filter = getFilter();
        HashMap hashMap2 = new HashMap();
        if (!(filter == null || filter.length() == 0)) {
            try {
                JSONObject jSONObject = new JSONObject(filter);
                Iterator<String> keys = jSONObject.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    String value = jSONObject.getString(key);
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    Intrinsics.checkNotNullExpressionValue(value, "value");
                    hashMap2.put(key, value);
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        hashMap.putAll(hashMap2);
        hashMap.put("page", String.valueOf(getCurrentPage()));
        Unit unit = Unit.INSTANCE;
        return C0917a.m222f(c0917a, "comics/blockList", HomeComicsBlockBean.class, hashMap, new Function1<List<? extends HomeComicsBlockBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.home.ComicsBlockListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends HomeComicsBlockBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends HomeComicsBlockBean> list) {
                ComicsBlockListFragment.this.didRequestComplete(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, null, false, false, null, false, 496);
    }

    public final void updateOrderBy(@Nullable String orderBy) {
        HashMap<String, String> mParams = getMParams();
        if (orderBy == null) {
            orderBy = "";
        }
        mParams.put("order_by", orderBy);
        reset();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseMutiListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull HomeComicsBlockBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        int itemType = item.getItemType();
        if (itemType == 1) {
            showComicsList(helper, item, R.layout.item_comic_layout, 0);
        } else if (itemType == 2) {
            showComicsList(helper, item, R.layout.item_comic_layout, 3);
        } else {
            if (itemType != 3) {
                return;
            }
            showComicsList(helper, item, R.layout.item_comic_layout, 2);
        }
    }
}
