package com.jbzd.media.movecartoons.p396ui.comics;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import kotlin.text.Typography;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2 extends Lambda implements Function0<C36691> {
    public final /* synthetic */ ComicsDetailInfoFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2(ComicsDetailInfoFragment comicsDetailInfoFragment) {
        super(0);
        this.this$0 = comicsDetailInfoFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5761invoke$lambda1$lambda0(ComicsDetailInfoFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean");
        ComicsDetailActivity.Companion companion = ComicsDetailActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String str = ((ComicsDetailInfoBean) item).f10010id;
        Intrinsics.checkNotNullExpressionValue(str, "mComicsDetailInfoBean.id");
        companion.start(requireContext, str);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C36691 invoke() {
        final ComicsDetailInfoFragment comicsDetailInfoFragment = this.this$0;
        ?? r0 = new BaseQuickAdapter<ComicsDetailInfoBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2.1
            {
                super(R.layout.item_comic_layout, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull ComicsDetailInfoBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                C2354n.m2463c2(ComicsDetailInfoFragment.this).m3298p(item.img).m3292f0().m757R((ImageView) helper.m3912b(R.id.img_cover));
                View view = helper.m3912b(R.id.img_cover);
                Intrinsics.checkNotNullParameter(view, "view");
                view.setOutlineProvider(new C0859m0(6.0d));
                view.setClipToOutline(true);
                helper.m3919i(R.id.tv_comics_name, item.name);
                helper.m3919i(R.id.tv_comics_category_subtitle, item.category + Typography.middleDot + ((Object) item.sub_title));
            }
        };
        final ComicsDetailInfoFragment comicsDetailInfoFragment2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.d.i
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2.m5761invoke$lambda1$lambda0(ComicsDetailInfoFragment.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
