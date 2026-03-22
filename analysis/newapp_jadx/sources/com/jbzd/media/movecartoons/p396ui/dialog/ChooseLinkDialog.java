package com.jbzd.media.movecartoons.p396ui.dialog;

import android.view.View;
import androidx.core.internal.view.SupportMenu;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.LinkBean;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010 \n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001BB\u0012\f\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00020\u0017\u0012\u0006\u0010\u001c\u001a\u00020\u0002\u0012#\b\u0002\u0010$\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b!\u0012\b\b\"\u0012\u0004\b\b(#\u0012\u0004\u0012\u00020\t0 ¢\u0006\u0004\b*\u0010+J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u001f\u0010\u000e\u001a\u0012\u0012\u0004\u0012\u00020\u00020\fj\b\u0012\u0004\u0012\u00020\u0002`\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ3\u0010\u0015\u001a\u00020\t2\u0012\u0010\u0011\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00060\u00102\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0014\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0015\u0010\u0016R\u001f\u0010\u0018\u001a\b\u0012\u0004\u0012\u00020\u00020\u00178\u0006@\u0006¢\u0006\f\n\u0004\b\u0018\u0010\u0019\u001a\u0004\b\u001a\u0010\u001bR\u0019\u0010\u001c\u001a\u00020\u00028\u0006@\u0006¢\u0006\f\n\u0004\b\u001c\u0010\u001d\u001a\u0004\b\u001e\u0010\u001fR=\u0010$\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b!\u0012\b\b\"\u0012\u0004\b\b(#\u0012\u0004\u0012\u00020\t0 8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b$\u0010%\u001a\u0004\b&\u0010'\"\u0004\b(\u0010)¨\u0006,"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/ChooseLinkDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/SelectBottomDialog;", "Lcom/jbzd/media/movecartoons/bean/response/LinkBean;", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/LinkBean;)V", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "getData", "()Ljava/util/ArrayList;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "", "list", "Ljava/util/List;", "getList", "()Ljava/util/List;", "currentStr", "Lcom/jbzd/media/movecartoons/bean/response/LinkBean;", "getCurrentStr", "()Lcom/jbzd/media/movecartoons/bean/response/LinkBean;", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "link", "submitBlock", "Lkotlin/jvm/functions/Function1;", "getSubmitBlock", "()Lkotlin/jvm/functions/Function1;", "setSubmitBlock", "(Lkotlin/jvm/functions/Function1;)V", "<init>", "(Ljava/util/List;Lcom/jbzd/media/movecartoons/bean/response/LinkBean;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ChooseLinkDialog extends SelectBottomDialog<LinkBean> {

    @NotNull
    private final LinkBean currentStr;

    @NotNull
    private final List<LinkBean> list;

    @NotNull
    private Function1<? super LinkBean, Unit> submitBlock;

    public /* synthetic */ ChooseLinkDialog(List list, LinkBean linkBean, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(list, linkBean, (i2 & 4) != 0 ? new Function1<LinkBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.ChooseLinkDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinkBean linkBean2) {
                invoke2(linkBean2);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinkBean link) {
                Intrinsics.checkNotNullParameter(link, "link");
            }
        } : function1);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final LinkBean getCurrentStr() {
        return this.currentStr;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    @NotNull
    public ArrayList<LinkBean> getData() {
        return (ArrayList) this.list;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public int getItemLayoutId() {
        return R.layout.item_link;
    }

    @NotNull
    public final List<LinkBean> getList() {
        return this.list;
    }

    @NotNull
    public final Function1<LinkBean, Unit> getSubmitBlock() {
        return this.submitBlock;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public void onItemClick(@NotNull BaseQuickAdapter<LinkBean, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        this.submitBlock.invoke(adapter.getItem(position));
        dismissAllowingStateLoss();
    }

    public final void setSubmitBlock(@NotNull Function1<? super LinkBean, Unit> function1) {
        Intrinsics.checkNotNullParameter(function1, "<set-?>");
        this.submitBlock = function1;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull LinkBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        helper.m3919i(R.id.text, item.getName());
        if (Intrinsics.areEqual(item, getCurrentStr())) {
            helper.m3920j(R.id.text, SupportMenu.CATEGORY_MASK);
        } else {
            helper.m3921k(R.id.text, R.color.font_bg_dark);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    public ChooseLinkDialog(@NotNull List<? extends LinkBean> list, @NotNull LinkBean currentStr, @NotNull Function1<? super LinkBean, Unit> submitBlock) {
        Intrinsics.checkNotNullParameter(list, "list");
        Intrinsics.checkNotNullParameter(currentStr, "currentStr");
        Intrinsics.checkNotNullParameter(submitBlock, "submitBlock");
        this.list = list;
        this.currentStr = currentStr;
        this.submitBlock = submitBlock;
    }
}
