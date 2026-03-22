package com.jbzd.media.movecartoons.p396ui.index.post.block;

import android.view.View;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.PostCategoryDetailBean;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity;
import com.jbzd.media.movecartoons.p396ui.index.post.block.PostCategoryDetailActivity$categoriesAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/post/block/PostCategoryDetailActivity$categoriesAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/index/post/block/PostCategoryDetailActivity$categoriesAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostCategoryDetailActivity$categoriesAdapter$2 extends Lambda implements Function0<C37721> {
    public final /* synthetic */ PostCategoryDetailActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PostCategoryDetailActivity$categoriesAdapter$2(PostCategoryDetailActivity postCategoryDetailActivity) {
        super(0);
        this.this$0 = postCategoryDetailActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5846invoke$lambda1$lambda0(PostCategoryDetailActivity this$0, BaseQuickAdapter adapter, View view, int i2) {
        PostCategoryDetailBean.CatInfoBean catInfoBean;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.PostCategoryDetailBean.CatInfoBean");
        PostCategoryDetailBean.CatInfoBean catInfoBean2 = (PostCategoryDetailBean.CatInfoBean) obj;
        PostCategoryDetailBean value = this$0.getViewModel().getMPostCategoryDetailBean().getValue();
        String str = null;
        if (value != null && (catInfoBean = value.cat_info) != null) {
            str = catInfoBean.position;
        }
        if (str != null) {
            PostCategoryDetailActivity.Companion companion = PostCategoryDetailActivity.INSTANCE;
            String str2 = catInfoBean2.f9973id;
            Intrinsics.checkNotNullExpressionValue(str2, "categoriesBean.id");
            companion.start(this$0, str2, str);
        }
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$categoriesAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37721 invoke() {
        final PostCategoryDetailActivity postCategoryDetailActivity = this.this$0;
        ?? r0 = new BaseQuickAdapter<PostCategoryDetailBean.CatInfoBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.post.block.PostCategoryDetailActivity$categoriesAdapter$2.1
            {
                super(R.layout.item_categories_module, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull PostCategoryDetailBean.CatInfoBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                PostCategoryDetailActivity postCategoryDetailActivity2 = PostCategoryDetailActivity.this;
                C2354n.m2467d2(postCategoryDetailActivity2).m3298p(item.img).m3295i0().m757R((ImageView) helper.m3912b(R.id.iv_img_categories));
                helper.m3919i(R.id.tv_name_categories, item.name);
                helper.m3919i(R.id.tv_name_post_count, Intrinsics.stringPlus(item.post_count, "个帖子"));
            }
        };
        final PostCategoryDetailActivity postCategoryDetailActivity2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.l.g.d
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                PostCategoryDetailActivity$categoriesAdapter$2.m5846invoke$lambda1$lambda0(PostCategoryDetailActivity.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
