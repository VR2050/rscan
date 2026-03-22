package com.jbzd.media.movecartoons.p396ui.index.selected.child;

import android.content.Context;
import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment;
import com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListFragment$tagAdapter$2;
import com.jbzd.media.movecartoons.p396ui.search.ModuleDetailActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$tagAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/index/selected/child/PlayListFragment$tagAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PlayListFragment$tagAdapter$2 extends Lambda implements Function0<C37861> {
    public final /* synthetic */ PlayListFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public PlayListFragment$tagAdapter$2(PlayListFragment playListFragment) {
        super(0);
        this.this$0 = playListFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5855invoke$lambda1$lambda0(PlayListFragment this$0, BaseQuickAdapter adapter, View noName_1, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(noName_1, "$noName_1");
        Object obj = adapter.getData().get(i2);
        Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        TagBean tagBean = (TagBean) obj;
        ModuleDetailActivity.Companion companion = ModuleDetailActivity.INSTANCE;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String str = tagBean.f10032id;
        if (str == null) {
            str = "";
        }
        companion.startTag(requireContext, str, tagBean.name);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$tagAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37861 invoke() {
        ?? r0 = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.index.selected.child.PlayListFragment$tagAdapter$2.1
            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                helper.m3919i(R.id.tv_content, Intrinsics.stringPlus("#", item.name));
            }
        };
        final PlayListFragment playListFragment = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.m.a.i
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                PlayListFragment$tagAdapter$2.m5855invoke$lambda1$lambda0(PlayListFragment.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
