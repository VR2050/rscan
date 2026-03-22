package com.jbzd.media.movecartoons.p396ui.dialog;

import android.view.View;
import android.widget.TextView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.p396ui.dialog.SelectTagDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.SelectTagDialog$adapter$2;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/dialog/SelectTagDialog$adapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/dialog/SelectTagDialog$adapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SelectTagDialog$adapter$2 extends Lambda implements Function0<C37321> {
    public final /* synthetic */ SelectTagDialog this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SelectTagDialog$adapter$2(SelectTagDialog selectTagDialog) {
        super(0);
        this.this$0 = selectTagDialog;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5787invoke$lambda1$lambda0(SelectTagDialog this$0, C37321 this_apply, BaseQuickAdapter adapter, View view, int i2) {
        TextView tvTitle;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.tag.TagBean");
        TagBean tagBean = (TagBean) item;
        if (this$0.getSelectList().contains(tagBean)) {
            this$0.getSelectList().remove(tagBean);
        } else if (this$0.getSelectList().size() < 3) {
            this$0.getSelectList().add(tagBean);
        } else {
            C2354n.m2379B1("最多选择三个标签哦");
        }
        tvTitle = this$0.getTvTitle();
        StringBuilder m586H = C1499a.m586H("选择喜欢的标签(");
        m586H.append(this$0.getSelectList().size());
        m586H.append("/3)");
        tvTitle.setText(m586H.toString());
        this_apply.notifyDataSetChanged();
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$adapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37321 invoke() {
        final SelectTagDialog selectTagDialog = this.this$0;
        final ?? r0 = new BaseQuickAdapter<TagBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.dialog.SelectTagDialog$adapter$2.1
            {
                super(R.layout.item_classify, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull TagBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                SelectTagDialog selectTagDialog2 = SelectTagDialog.this;
                helper.m3919i(R.id.tvText, item.name);
                ((TextView) helper.m3912b(R.id.tvText)).setSelected(selectTagDialog2.getSelectList().contains(item));
            }
        };
        final SelectTagDialog selectTagDialog2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.w
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                SelectTagDialog$adapter$2.m5787invoke$lambda1$lambda0(SelectTagDialog.this, r0, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
