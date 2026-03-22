package com.jbzd.media.movecartoons.p396ui.index.post;

import android.view.View;
import android.widget.TextView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.PostHomeResponse;
import com.jbzd.media.movecartoons.p396ui.index.post.CommunityTabSingleFragment$bloggerAdapter$2;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$bloggerAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$bloggerAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class CommunityTabSingleFragment$bloggerAdapter$2 extends Lambda implements Function0<C37681> {
    public final /* synthetic */ CommunityTabSingleFragment this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\n*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\r\u0010\u000eJ\r\u0010\u000f\u001a\u00020\t¢\u0006\u0004\b\u000f\u0010\u0010R\u0016\u0010\u0011\u001a\u00020\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0011\u0010\u0012¨\u0006\u0013"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/post/CommunityTabSingleFragment$bloggerAdapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$HLSFollowerBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$HLSFollowerBean;)V", "", "position", "setSelectedPosition", "(I)V", "getSelectedItem", "()Lcom/jbzd/media/movecartoons/bean/response/PostHomeResponse$HLSFollowerBean;", "getSelectP", "()I", "mSelectP", "I", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    /* renamed from: com.jbzd.media.movecartoons.ui.index.post.CommunityTabSingleFragment$bloggerAdapter$2$1 */
    public static final class C37681 extends BaseQuickAdapter<PostHomeResponse.HLSFollowerBean, BaseViewHolder> {
        private int mSelectP;
        public final /* synthetic */ CommunityTabSingleFragment this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C37681(CommunityTabSingleFragment communityTabSingleFragment) {
            super(R.layout.item_subscription_head, null, 2, null);
            this.this$0 = communityTabSingleFragment;
        }

        /* renamed from: getSelectP, reason: from getter */
        public final int getMSelectP() {
            return this.mSelectP;
        }

        @Nullable
        public final PostHomeResponse.HLSFollowerBean getSelectedItem() {
            try {
                return getData().get(this.mSelectP);
            } catch (Exception unused) {
                return null;
            }
        }

        public final void setSelectedPosition(int position) {
            this.mSelectP = position;
            notifyDataSetChanged();
        }

        @Override // com.chad.library.adapter.base.BaseQuickAdapter
        public void convert(@NotNull BaseViewHolder helper, @NotNull PostHomeResponse.HLSFollowerBean item) {
            Intrinsics.checkNotNullParameter(helper, "helper");
            Intrinsics.checkNotNullParameter(item, "item");
            CommunityTabSingleFragment communityTabSingleFragment = this.this$0;
            CircleImageView circleImageView = (CircleImageView) helper.m3912b(R.id.civ_head);
            helper.m3916f(R.id.iv_subheader_vip, !Intrinsics.areEqual(item.is_up, "y"));
            TextView textView = (TextView) helper.m3912b(R.id.tv_nickname);
            circleImageView.setSelected(this.mSelectP == helper.getLayoutPosition());
            textView.setSelected(circleImageView.isSelected());
            C2852c m2463c2 = C2354n.m2463c2(communityTabSingleFragment);
            String str = item.img;
            if (str == null) {
                str = "";
            }
            C1558h mo770c = m2463c2.mo770c();
            mo770c.mo763X(str);
            ((C2851b) mo770c).m3292f0().m757R(circleImageView);
            String str2 = item.nickname;
            helper.m3919i(R.id.tv_nickname, str2 != null ? str2 : "");
            helper.m3920j(R.id.tv_nickname, circleImageView.isSelected() ? communityTabSingleFragment.requireContext().getResources().getColor(R.color.color_gold_main) : communityTabSingleFragment.requireContext().getResources().getColor(R.color.white));
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public CommunityTabSingleFragment$bloggerAdapter$2(CommunityTabSingleFragment communityTabSingleFragment) {
        super(0);
        this.this$0 = communityTabSingleFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5841invoke$lambda1$lambda0(C37681 this_apply, CommunityTabSingleFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        if (this_apply.getMSelectP() != i2) {
            this_apply.setSelectedPosition(i2);
            Object obj = adapter.getData().get(i2);
            Objects.requireNonNull(obj, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.PostHomeResponse.HLSFollowerBean");
            this$0.getViewModel().getCurrentBloggerId().setValue(((PostHomeResponse.HLSFollowerBean) obj).f9978id.toString());
        }
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37681 invoke() {
        final C37681 c37681 = new C37681(this.this$0);
        final CommunityTabSingleFragment communityTabSingleFragment = this.this$0;
        c37681.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.g.l.e
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                CommunityTabSingleFragment$bloggerAdapter$2.m5841invoke$lambda1$lambda0(CommunityTabSingleFragment$bloggerAdapter$2.C37681.this, communityTabSingleFragment, baseQuickAdapter, view, i2);
            }
        });
        return c37681;
    }
}
