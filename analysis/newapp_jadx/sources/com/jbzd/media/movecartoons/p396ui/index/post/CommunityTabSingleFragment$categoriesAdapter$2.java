package com.jbzd.media.movecartoons.p396ui.index.post;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment;
import com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment$categoriesAdapter$2;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$categoriesAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$categoriesAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommunityTabSingleFragment$categoriesAdapter$2 extends Lambda implements Function0<C37691> {
    public final /* synthetic */ CommunityTabSingleFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CommunityTabSingleFragment$categoriesAdapter$2(CommunityTabSingleFragment communityTabSingleFragment) {
        super(0);
        this.this$0 = communityTabSingleFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5842invoke$lambda1$lambda0(CommunityTabSingleFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.PostHomeResponse.CategoriesBean");
        PostHomeResponse.CategoriesBean categoriesBean = (PostHomeResponse.CategoriesBean) obj;
        PostCategoryDetailActivity.Companion companion = PostCategoryDetailActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String str = categoriesBean.f9977id;
        Intrinsics.checkNotNullExpressionValue(str, "categoriesBean.id");
        String str2 = categoriesBean.position;
        Intrinsics.checkNotNullExpressionValue(str2, "categoriesBean.position");
        companion.start(requireContext, str, str2);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$categoriesAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37691 invoke() {
        final CommunityTabSingleFragment communityTabSingleFragment = this.this$0;
        ?? r0 = new BaseQuickAdapter<PostHomeResponse.CategoriesBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$categoriesAdapter$2.1
            {
                super(R.layout.item_categories_module, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull PostHomeResponse.CategoriesBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                CommunityTabSingleFragment communityTabSingleFragment2 = CommunityTabSingleFragment.this;
                C2354n.m2455a2(communityTabSingleFragment2.requireContext()).m3298p(item.img).m3295i0().m757R((ImageView) helper.m3912b(R.id.iv_img_categories));
                View view = helper.m3912b(R.id.iv_img_categories);
                Intrinsics.checkNotNullParameter(view, "view");
                view.setOutlineProvider(new C0859m0(5.0d));
                view.setClipToOutline(true);
                helper.m3919i(R.id.tv_name_categories, item.name);
                helper.m3919i(R.id.tv_name_post_count, Intrinsics.stringPlus(item.post_count, "个帖子"));
            }
        };
        final CommunityTabSingleFragment communityTabSingleFragment2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.l.f
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                CommunityTabSingleFragment$categoriesAdapter$2.m5842invoke$lambda1$lambda0(CommunityTabSingleFragment.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
