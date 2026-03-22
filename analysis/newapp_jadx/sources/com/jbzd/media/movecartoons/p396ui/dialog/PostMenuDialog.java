package com.jbzd.media.movecartoons.p396ui.dialog;

import android.view.View;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010!\n\u0002\b\u0007\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B:\u0012\f\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\u00020\u001e\u0012#\b\u0002\u0010\u001a\u001a\u001d\u0012\u0013\u0012\u00110\u0003¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u0014\u0012\u0004\u0012\u00020\t0\u0017¢\u0006\u0004\b#\u0010$J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u001f\u0010\n\u001a\u00020\t2\u0006\u0010\u0007\u001a\u00020\u00062\u0006\u0010\b\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u001f\u0010\u000e\u001a\u0012\u0012\u0004\u0012\u00020\u00020\fj\b\u0012\u0004\u0012\u00020\u0002`\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ3\u0010\u0015\u001a\u00020\t2\u0012\u0010\u0011\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00060\u00102\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0014\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0015\u0010\u0016R4\u0010\u001a\u001a\u001d\u0012\u0013\u0012\u00110\u0003¢\u0006\f\b\u0018\u0012\b\b\u0019\u0012\u0004\b\b(\u0014\u0012\u0004\u0012\u00020\t0\u00178\u0006@\u0006¢\u0006\f\n\u0004\b\u001a\u0010\u001b\u001a\u0004\b\u001c\u0010\u001dR\u001f\u0010\u001f\u001a\b\u0012\u0004\u0012\u00020\u00020\u001e8\u0006@\u0006¢\u0006\f\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"¨\u0006%"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/dialog/PostMenuDialog;", "Lcom/jbzd/media/movecartoons/ui/dialog/SelectBottomDialog;", "", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/String;)V", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "getData", "()Ljava/util/ArrayList;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "onItemCLick", "Lkotlin/jvm/functions/Function1;", "getOnItemCLick", "()Lkotlin/jvm/functions/Function1;", "", "list", "Ljava/util/List;", "getList", "()Ljava/util/List;", "<init>", "(Ljava/util/List;Lkotlin/jvm/functions/Function1;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class PostMenuDialog extends SelectBottomDialog<String> {

    @NotNull
    private final List<String> list;

    @NotNull
    private final Function1<Integer, Unit> onItemCLick;

    /* JADX WARN: Multi-variable type inference failed */
    public PostMenuDialog(@NotNull List<String> list, @NotNull Function1<? super Integer, Unit> onItemCLick) {
        Intrinsics.checkNotNullParameter(list, "list");
        Intrinsics.checkNotNullParameter(onItemCLick, "onItemCLick");
        this.list = list;
        this.onItemCLick = onItemCLick;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    @NotNull
    public ArrayList<String> getData() {
        return (ArrayList) this.list;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public int getItemLayoutId() {
        return R.layout.item_link;
    }

    @NotNull
    public final List<String> getList() {
        return this.list;
    }

    @NotNull
    public final Function1<Integer, Unit> getOnItemCLick() {
        return this.onItemCLick;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public void onItemClick(@NotNull BaseQuickAdapter<String, BaseViewHolder> adapter, @NotNull View view, int position) {
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        super.onItemClick(adapter, view, position);
        dismissAllowingStateLoss();
        this.onItemCLick.invoke(Integer.valueOf(position));
    }

    public /* synthetic */ PostMenuDialog(List list, Function1 function1, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(list, (i2 & 2) != 0 ? new Function1<Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.dialog.PostMenuDialog.1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Integer num) {
                invoke(num.intValue());
                return Unit.INSTANCE;
            }

            public final void invoke(int i3) {
            }
        } : function1);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull String item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        helper.m3919i(R.id.text, item);
    }
}
