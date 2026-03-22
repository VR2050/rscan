package com.jbzd.media.movecartoons.p396ui.search.child;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean;
import com.jbzd.media.movecartoons.p396ui.novel.NovelDetailActivity;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0844f;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000^\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\b\u0018\u0000 (2\u00020\u0001:\u0001(B\u0007¢\u0006\u0004\b&\u0010'J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J+\u0010\u0007\u001a\u001e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00020\u0005j\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u0002`\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u001f\u0010\u0011\u001a\u00020\u00102\u0006\u0010\r\u001a\u00020\f2\u0006\u0010\u000f\u001a\u00020\u000eH\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u0011\u0010\u0014\u001a\u0004\u0018\u00010\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J3\u0010\u001b\u001a\u00020\u00102\u0012\u0010\u0017\u001a\u000e\u0012\u0004\u0012\u00020\u000e\u0012\u0004\u0012\u00020\f0\u00162\u0006\u0010\u0019\u001a\u00020\u00182\u0006\u0010\u001a\u001a\u00020\tH\u0016¢\u0006\u0004\b\u001b\u0010\u001cJ\u000f\u0010\u001e\u001a\u00020\u001dH\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\u0002H\u0016¢\u0006\u0004\b \u0010\u0004J\u0011\u0010\"\u001a\u0004\u0018\u00010!H\u0016¢\u0006\u0004\b\"\u0010#J\u000f\u0010$\u001a\u00020\tH\u0016¢\u0006\u0004\b$\u0010\u000bJ\u000f\u0010%\u001a\u00020\tH\u0016¢\u0006\u0004\b%\u0010\u000b¨\u0006)"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonNovelListFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/BaseListNovelFragment;", "", "getRequestUrl", "()Ljava/lang/String;", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "getRequestBody", "()Ljava/util/HashMap;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelItemsBean;", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/novel/NovelItemsBean;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getEmptyTips", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getLeftPadding", "getRightPadding", "<init>", "()V", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommonNovelListFragment extends BaseListNovelFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ7\u0010\u0007\u001a\u00020\u00062(\b\u0002\u0010\u0005\u001a\"\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u00010\u0002j\u0010\u0012\u0004\u0012\u00020\u0003\u0012\u0004\u0012\u00020\u0003\u0018\u0001`\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/CommonNovelListFragment$Companion;", "", "Ljava/util/HashMap;", "", "Lkotlin/collections/HashMap;", "map", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonNovelListFragment;", "newInstance", "(Ljava/util/HashMap;)Lcom/jbzd/media/movecartoons/ui/search/child/CommonNovelListFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ CommonNovelListFragment newInstance$default(Companion companion, HashMap hashMap, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                hashMap = null;
            }
            return companion.newInstance(hashMap);
        }

        @NotNull
        public final CommonNovelListFragment newInstance(@Nullable HashMap<String, String> map) {
            CommonNovelListFragment commonNovelListFragment = new CommonNovelListFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("params_map", map);
            Unit unit = Unit.INSTANCE;
            commonNovelListFragment.setArguments(bundle);
            return commonNovelListFragment;
        }
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseListNovelFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public String getEmptyTips() {
        return "当前页面暂无内容";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public RecyclerView.ItemDecoration getItemDecoration() {
        GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(getContext());
        c4053a.m4576a(R.color.transparent);
        c4053a.f10336d = C2354n.m2437V(getContext(), 8.0d);
        c4053a.f10337e = C2354n.m2437V(getContext(), 5.0d);
        c4053a.f10339g = false;
        c4053a.f10340h = false;
        c4053a.f10338f = false;
        return new GridItemDecoration(c4053a);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_novel_layout;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new GridLayoutManager(getContext(), 3);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return C2354n.m2425R(requireContext(), 5.0f);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseListNovelFragment
    @NotNull
    public HashMap<String, String> getRequestBody() {
        Bundle arguments = getArguments();
        Serializable serializable = arguments == null ? null : arguments.getSerializable("params_map");
        Objects.requireNonNull(serializable, "null cannot be cast to non-null type java.util.HashMap<kotlin.String, kotlin.String>{ kotlin.collections.TypeAliasesKt.HashMap<kotlin.String, kotlin.String> }");
        return (HashMap) serializable;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseListNovelFragment
    @NotNull
    public String getRequestUrl() {
        return "novel/search";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return C2354n.m2425R(requireContext(), 5.0f);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void onItemClick(@NotNull BaseQuickAdapter<NovelItemsBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        NovelItemsBean bean = adapter.getData().get(position);
        if (!bean.getType().equals("ad")) {
            NovelDetailActivity.Companion companion = NovelDetailActivity.INSTANCE;
            Context requireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            String id = bean.getId();
            Intrinsics.checkNotNullExpressionValue(id, "mNovelItemsBean.id");
            companion.start(requireContext, id);
            return;
        }
        C0840d.a aVar = C0840d.f235a;
        Context context = requireContext();
        Intrinsics.checkNotNullExpressionValue(context, "requireContext()");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(bean, "bean");
        String id2 = bean.getId();
        Intrinsics.checkNotNullExpressionValue(id2, "bean.id");
        String name = bean.getName();
        Intrinsics.checkNotNullExpressionValue(name, "bean.name");
        Intrinsics.checkNotNullParameter("app", "type");
        Intrinsics.checkNotNullParameter(id2, "id");
        Intrinsics.checkNotNullParameter(name, "name");
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("object_type", "app", "object_id", id2);
        m596R.put("object_name", name);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "system/track", Object.class, m596R, C0844f.f245c, null, false, false, null, false, 432);
        C0840d.a.m174d(aVar, context, bean.link, null, null, 12);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        getRequestRoomParameter().putAll(getRequestBody());
        getRequestRoomParameter().put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, getRequestUrl(), NovelItemsBean.class, getRequestRoomParameter(), new Function1<List<? extends NovelItemsBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonNovelListFragment$request$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends NovelItemsBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends NovelItemsBean> list) {
                if (CommonNovelListFragment.this.getCurrentPage() == 1) {
                    CommonNovelListFragment.this.didRequestComplete(list);
                    return;
                }
                if (!(list == null || list.isEmpty()) && list.size() >= 10) {
                    CommonNovelListFragment.this.didRequestComplete(list);
                    return;
                }
                C1318f loadMoreModule = CommonNovelListFragment.this.getAdapter().getLoadMoreModule();
                if (loadMoreModule == null) {
                    return;
                }
                C1318f.m324h(loadMoreModule, false, 1, null);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.CommonNovelListFragment$request$2
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
                CommonNovelListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull NovelItemsBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        if (Intrinsics.areEqual(item.getType(), "ad")) {
            C2354n.m2463c2(this).m3298p(item.getImg_x()).m3292f0().m757R((ImageView) helper.m3912b(R.id.img_cover));
        } else {
            C2354n.m2463c2(this).m3298p(item.getImg()).m3292f0().m757R((ImageView) helper.m3912b(R.id.img_cover));
        }
        View view = helper.m3912b(R.id.img_cover);
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(8.0d));
        view.setClipToOutline(true);
        helper.m3919i(R.id.tv_novel_name, item.getName());
        helper.m3919i(R.id.tv_novel_category_subtitle, item.getCategory_name() + Typography.middleDot + ((Object) item.getSub_title()));
        if (item.getType().equals("ad")) {
            ((TextView) helper.m3912b(R.id.tv_ad_new_novel)).setVisibility(0);
            ((TextView) helper.m3912b(R.id.tv_novel_name)).setVisibility(8);
            ((TextView) helper.m3912b(R.id.tv_novel_category_subtitle)).setVisibility(8);
        } else {
            ((TextView) helper.m3912b(R.id.tv_ad_new_novel)).setVisibility(8);
            ((TextView) helper.m3912b(R.id.tv_novel_name)).setVisibility(0);
            ((TextView) helper.m3912b(R.id.tv_novel_category_subtitle)).setVisibility(0);
            helper.m3916f(R.id.iv_novel_audio, !item.getIco().equals("audio"));
        }
    }
}
