package com.jbzd.media.movecartoons.p396ui.welfare;

import android.view.View;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.ScoreBean;
import com.jbzd.media.movecartoons.p396ui.welfare.ChangeScoreFragment$groupAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment$groupAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment$groupAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ChangeScoreFragment$groupAdapter$2 extends Lambda implements Function0<C39051> {
    public final /* synthetic */ ChangeScoreFragment this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000%\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u0001J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0005\u001a\u00020\u0002H\u0014¢\u0006\u0004\b\u0007\u0010\bJ\u0015\u0010\u000b\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t¢\u0006\u0004\b\u000b\u0010\fR\u0016\u0010\r\u001a\u00020\t8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\r\u0010\u000e¨\u0006\u000f"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/welfare/ChangeScoreFragment$groupAdapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/ScoreBean$ExchangeItem;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "holder", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/ScoreBean$ExchangeItem;)V", "", "position", "setSelectedPosition", "(I)V", "mSelectGroup", "I", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    /* renamed from: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$groupAdapter$2$1 */
    public static final class C39051 extends BaseQuickAdapter<ScoreBean.ExchangeItem, BaseViewHolder> {
        private int mSelectGroup;
        public final /* synthetic */ ChangeScoreFragment this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C39051(ChangeScoreFragment changeScoreFragment) {
            super(R.layout.item_exchange_code, null, 2, null);
            this.this$0 = changeScoreFragment;
        }

        public final void setSelectedPosition(int position) {
            this.mSelectGroup = position;
            if (position >= getData().size()) {
                this.mSelectGroup = 0;
            }
            notifyDataSetChanged();
        }

        @Override // com.chad.library.adapter.base.BaseQuickAdapter
        public void convert(@NotNull BaseViewHolder holder, @NotNull final ScoreBean.ExchangeItem item) {
            Intrinsics.checkNotNullParameter(holder, "holder");
            Intrinsics.checkNotNullParameter(item, "item");
            ((ConstraintLayout) holder.m3912b(R.id.ll_score_change)).setSelected(this.mSelectGroup == holder.getAdapterPosition());
            holder.m3919i(R.id.tvTitle, Intrinsics.stringPlus(item.day, "天VIP"));
            holder.m3919i(R.id.tvTips, item.num + "积分");
            View m3912b = holder.m3912b(R.id.tv_sign_now);
            final ChangeScoreFragment changeScoreFragment = this.this$0;
            C2354n.m2374A(m3912b, 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.welfare.ChangeScoreFragment$groupAdapter$2$1$convert$1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                    invoke2(textView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull TextView it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    ChangeScoreFragment.this.mProductsBean = item;
                    ChangeScoreFragment.this.doExchange();
                }
            }, 1);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ChangeScoreFragment$groupAdapter$2(ChangeScoreFragment changeScoreFragment) {
        super(0);
        this.this$0 = changeScoreFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m6024invoke$lambda1$lambda0(C39051 this_apply, ChangeScoreFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.ScoreBean.ExchangeItem");
        this_apply.setSelectedPosition(i2);
        this$0.mProductsBean = (ScoreBean.ExchangeItem) item;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C39051 invoke() {
        final C39051 c39051 = new C39051(this.this$0);
        final ChangeScoreFragment changeScoreFragment = this.this$0;
        c39051.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.t.b
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                ChangeScoreFragment$groupAdapter$2.m6024invoke$lambda1$lambda0(ChangeScoreFragment$groupAdapter$2.C39051.this, changeScoreFragment, baseQuickAdapter, view, i2);
            }
        });
        return c39051;
    }
}
