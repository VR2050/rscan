package com.jbzd.media.movecartoons.p396ui.dialog;

import android.view.View;
import androidx.exifinterface.media.ExifInterface;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.SelectBottomDialog$adapter$2;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p067b.p068a.p069a.p070a.p078m.InterfaceC1320h;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\t\n\u0000\n\u0002\b\u0003*\u0001\u0001\u0010\u0002\u001a\b\u0012\u0004\u0012\u00028\u00000\u0001\"\u0004\b\u0000\u0010\u0000H\n¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {ExifInterface.GPS_DIRECTION_TRUE, "com/jbzd/media/movecartoons/ui/dialog/SelectBottomDialog$adapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/dialog/SelectBottomDialog$adapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SelectBottomDialog$adapter$2 extends Lambda implements Function0<C37301> {
    public final /* synthetic */ SelectBottomDialog<T> this$0;

    /* JADX INFO: Add missing generic type declarations: [T] */
    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001d\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003*\u0001\u0000\b\n\u0018\u00002\u000e\u0012\u0004\u0012\u00028\u0000\u0012\u0004\u0012\u00020\u00020\u00012\u00020\u0003J\u001f\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0004\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00028\u0000H\u0014¢\u0006\u0004\b\u0007\u0010\b¨\u0006\t"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/dialog/SelectBottomDialog$adapter$2$1", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Lb/b/a/a/a/m/h;", "helper", "item", "", "convert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Ljava/lang/Object;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    /* renamed from: com.jbzd.media.movecartoons.ui.dialog.SelectBottomDialog$adapter$2$1 */
    public static final class C37301<T> extends BaseQuickAdapter<T, BaseViewHolder> implements InterfaceC1320h {
        public final /* synthetic */ SelectBottomDialog<T> this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C37301(SelectBottomDialog<T> selectBottomDialog, int i2) {
            super(i2, null, 2, null);
            this.this$0 = selectBottomDialog;
        }

        @Override // com.chad.library.adapter.base.BaseQuickAdapter
        public void convert(@NotNull BaseViewHolder helper, T item) {
            Intrinsics.checkNotNullParameter(helper, "helper");
            this.this$0.bindItem(helper, item);
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public SelectBottomDialog$adapter$2(SelectBottomDialog<T> selectBottomDialog) {
        super(0);
        this.this$0 = selectBottomDialog;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5786invoke$lambda1$lambda0(SelectBottomDialog this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        this$0.onItemClick(adapter, view, i2);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C37301 invoke() {
        C37301 c37301 = new C37301(this.this$0, this.this$0.getItemLayoutId());
        final SelectBottomDialog<T> selectBottomDialog = this.this$0;
        c37301.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.v
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                SelectBottomDialog$adapter$2.m5786invoke$lambda1$lambda0(SelectBottomDialog.this, baseQuickAdapter, view, i2);
            }
        });
        return c37301;
    }
}
